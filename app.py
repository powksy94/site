from flask import Flask, flash,  request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Import de Migrate
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity,  verify_jwt_in_request
import zipfile
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import sqlite3
from io import BytesIO
from flask_socketio import SocketIO
from datetime import datetime
import dns.resolver
import validators
from urllib.parse import urlparse
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app)
app.secret_key = os.urandom(24)  # Clé secrète pour sécuriser les sessions
# Clé secrète pour signer les jetons
app.config['JWT_SECRET_KEY'] = 'votre_clé_secrète'

# Initialiser JWT Manager
jwt = JWTManager(app)


db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialiser Migrate avec votre app et db



    
# Définition de la classe FileLog avec le champ 'domain'
class FileLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(100))
    filename = db.Column(db.String(100))
    exe_found = db.Column(db.Boolean, default=False)
    apk_found = db.Column(db.Boolean, default=False)
    msi_found = db.Column(db.Boolean, default=False)
    bat_found = db.Column(db.Boolean, default=False)
    domain = db.Column(db.String(255), nullable=True)  # Le champ domain est ajouté ici

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    status_code = db.Column(db.String)
    method = db.Column(db.String)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# Définition du modèle User avec SQLAlchemy
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    entreprise = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    # Méthode pour vérifier le mot de passe haché
    def check_password(self, password):
        return check_password_hash(self.password, password)


@app.route('/logs')
def logs():
        # Code pour récupérer et afficher les logs depuis la base de données ou autre source
        logs = FileLog.query.all()  # Exemple d'accès à la base de données
        return render_template('logs.html', logs=logs)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
        # Supprimer tous les logs de la base de données
        FileLog.query.delete()
        db.session.commit()
        return redirect(url_for('logs'))  # Rediriger vers la page des logs après suppression

with app.app_context():
     db.create_all()

@app.route('/about')
def about():
    return render_template('about_us.html')  # Changez 'about.html' par 'about_us.html'

def get_db_connection():
    conn = sqlite3.connect('logs.db')
    conn.row_factory = sqlite3.Row
    return conn

def verify_zip(zip_ref):
    """
    Fonction qui vérifie si un fichier ZIP contient des fichiers
    avec des extensions spécifiques (.exe, .apk, .msi, .bat).
    Retourne un dictionnaire avec les résultats pour chaque type de fichier.
    """
    found_files = {'exe': False, 'apk': False, 'msi': False, 'bat': False}

    # Parcours du contenu du fichier ZIP
    for file_name in zip_ref.namelist():
        if file_name.endswith('.exe'):
            found_files['exe'] = True
        elif file_name.endswith('.apk'):
            found_files['apk'] = True
        elif file_name.endswith('.msi'):
            found_files['msi'] = True
        elif file_name.endswith('.bat'):
            found_files['bat'] = True

    return found_files
# Fonction de vérification de domaine
def verify_domain(domain):
    """ Vérifier si le domaine est valide et accessible """
    # Vérifier si l'URL est valide (format du nom de domaine)
    if not validators.domain(domain):
        return False, "Nom de domaine invalide"
    
    try:
        # Vérifier si le domaine a un enregistrement DNS valide (ex. enregistrement A)
        dns.resolver.resolve(domain, 'A')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False, "Le domaine n'a pas d'enregistrement DNS valide"
    
    # Vérification si le domaine est accessible via HTTP
    try:
        response = requests.get(f'http://{domain}')
        if response.status_code == 200:
            return True, "Le domaine est valide et accessible"
        else:
            return False, f"Le domaine n'est pas accessible (Code HTTP {response.status_code})"
    except requests.exceptions.RequestException as e:
        return False, f"Erreur lors de la connexion au domaine: {str(e)}"

# Nouvelle fonction pour extraire le domaine de l'URL de manière robuste
def get_domain_from_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

# Ajout d'un utilisateur avec un mot de passe haché
def add_user(username, password, email, entreprise, role='user'):
    # Vérifier si l'utilisateur existe déjà
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"L'utilisateur '{username}' existe déjà.")
        return  # On arrête ici sans recréer

    # Hachage du mot de passe
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256:100000', salt_length=16)

    # Ajouter l'utilisateur
    user = User(username=username, email=email, entreprise=entreprise, password=hashed_password, role=role)
    db.session.add(user)
    db.session.commit()
    print(f"Utilisateur '{username}' créé avec succès !")

# Fonction de vérification de l'utilisateur avec un mot de passe
def verify_user(username, password):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    stored_password = cursor.fetchone()
    conn.close()

    if stored_password and check_password_hash(stored_password[0], password):
        return True
    return False

# Initialisation de la base de données
with app.app_context():
    # Exemple d'ajout d'un utilisateur
    add_user('admin', 'password123', 'example@gmail.com', 'Twitter')
    db.create_all()
    


    # Exemple de vérification du mot de passe
    username = 'admin'
    password = 'password123'

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        print("Le mot de passe est correct!")
    else:
        print("Le mot de passe est incorrect!")

# Endpoint pour se connecter et obtenir un jeton JWT
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vérifier si l'utilisateur existe dans la base de données
        user = User.query.filter_by(username=username).first()

        if user:
            # Vérifier si le mot de passe est correct
            if check_password_hash(user.password, password):  # Utilisez check_password_hash pour vérifier le mot de passe
                # Générer un jeton JWT pour cet utilisateur
                access_token = create_access_token(identity=username)

                # Vérifier le rôle de l'utilisateur
                if user.role == 'admin':
                    flash('Connexion réussie en tant qu\'administrateur !', 'success')
                else:
                    flash('Connexion réussie en tant qu\'utilisateur !', 'success')

                # Renvoie le jeton JWT dans la réponse
                return jsonify(access_token=access_token), 200  # Renvoyer le jeton JWT

            else:
                flash('Mot de passe incorrect', 'danger')
                return redirect(url_for('login'))  # Rediriger vers la page de login avec un message d'erreur
        else:
            flash('Nom d\'utilisateur non trouvé', 'danger')
            return redirect(url_for('login'))  # Rediriger vers la page de login avec un message d'erreur

    # Afficher le formulaire de connexion si la méthode est GET
    return render_template('login.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        entreprise = request.form['entreprise']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Vérification des champs
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Nom d'utilisateur ou e-mail déjà utilisé.", 'danger')
            return redirect(url_for('register'))

        # Création de l'utilisateur
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Inscription réussie. Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/analyze_data')
def analyze_data():
    """Route principale pour l'analyse des données."""

    # Accès local : pas besoin de JWT
    if request.remote_addr == '127.0.0.1' or request.host.startswith('localhost'):
        logs = fetch_logs()
        return render_template('analyze_data.html', logs=logs)

    # Accès distant : vérification JWT
    try:
        verify_jwt_in_request()
        logs = fetch_logs()
        return render_template('analyze_data.html', logs=logs)
    except Exception:
        return jsonify({"error": "Jeton invalide ou accès non autorisé"}), 401

def fetch_logs():
    return Log.query.order_by(Log.timestamp.desc()).all()


@app.route('/logout')
def logout():
    session.pop('username', None)  # Déconnecter l'utilisateur
    return redirect(url_for('home'))

# Exemple de données utilisateur
users = {
    "admin": {
        "username": "admin",
        "role": "administrator",
        "email": "admin@example.com"
    }
}

@app.route('/api/user', methods=['GET'])
def get_user_info():
    # Vérification de l'adresse IP du client
    client_ip = request.remote_addr
    if client_ip != '127.0.0.1':  # Permet l'accès uniquement à partir de localhost
        return jsonify({"error": "Accès interdit à cette ressource."}), 403

    # Si l'utilisateur est authentifié, retourner les données de l'utilisateur
    token = request.headers.get('Authorization')
    if token:
        # Exemple de vérification de jeton (pour simplifier ici)
        if token == "Bearer fake_jwt_token_for_localhost":  # Exemples de jeton à vérifier
            user_data = users.get("admin")
            return jsonify(user_data)
        else:
            return jsonify({"error": "Jeton invalide ou manquant"}), 401
    else:
        return jsonify({"error": "Jeton manquant"}), 401


@app.route('/')
def homepage():
    # Cette route n'a pas besoin de vérifier le jeton JWT
    return render_template('/Homepage.html')


@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    url = request.form['target_url']
    method = 'GET'
    try:
        response = requests.get(url, timeout=5)
        status_code = str(response.status_code)
    except Exception as e:
        status_code = f"Erreur: {str(e)}"

    conn = get_db_connection()
    conn.execute('INSERT INTO logs (url, status_code, method) VALUES (?, ?, ?)',
                 (url, status_code, method))
    conn.commit()
    conn.close()

    return redirect(url_for('analyze_data'))



@app.route('/index')
def index():
    return render_template('index.html')

# Fonction pour vérifier le jeton (pour simplification)
def verify_token(token):
    return token == "Bearer fake_jwt_token_for_localhost"

@app.route('/dev_monitor', methods=['GET'])
def dev_monitor():
    # Vérifier si la requête provient de localhost
    if request.remote_addr == '127.0.0.1':
        # Si la requête provient de localhost, on contourne la vérification du jeton
        return jsonify({"message": "Accès autorisé depuis localhost sans jeton"})and render_template('dev_monitor.html')
    
    # Si la requête ne provient pas de localhost, on vérifie le jeton d'authentification
    token = request.headers.get('Authorization')
    if token:
        if verify_token(token):
            return jsonify({"message": "Accès autorisé avec jeton"})
        else:
            return jsonify({"error": "Jeton invalide"}), 401
    else:
        return jsonify({"error": "Jeton manquant"}), 401


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/upload-url', methods=['POST'])
def upload_url():
    url = request.form['url']

    try:
        # Extraire le domaine de l'URL
        domain = get_domain_from_url(url)

        # Vérification du nom de domaine
        domain_valid, domain_message = verify_domain(domain)

        # Si le domaine n'est pas valide, retourner un message d'erreur
        if not domain_valid:
            return render_template('upload_url.html', status="error", message=domain_message)

        # Effectuer l'appel HTTP pour télécharger le fichier
        response = requests.get(url)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')

        result = {'exe': False, 'apk': False, 'msi': False, 'bat': False}

            # Vérification si le contenu est un fichier ZIP
        if 'zip' in content_type or 'octet-stream' in content_type:
            try:
                # Vérification si le contenu est bien un fichier ZIP
                zip_file = BytesIO(response.content)
                
                # Assurez-vous que le fichier est un ZIP valide
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    # Si c'est un fichier ZIP valide, on vérifie les types de fichiers dedans
                    result = verify_zip(zip_ref)
                    if any(result.values()):
                        message = "Fichier ZIP vérifié avec succès !"
                        status = "success"
                    else:
                        message = "Aucun fichier .exe, .apk, .msi ou .bat trouvé dans le ZIP."
                        status = "error"
            except zipfile.BadZipFile:
                # Si le fichier n'est pas un ZIP valide
                message = "Le fichier n'est pas un ZIP valide."
                status = "error"
            except Exception as e:
                # Gestion des autres erreurs potentielles
                message = f"Erreur lors de l'analyse du fichier ZIP : {str(e)}"
                status = "error"


        # Vérification si le contenu est un fichier spécifique
        elif 'octet-stream' in content_type:
            file_name = url.split("/")[-1].lower()
            if file_name.endswith('.exe'):
                result['exe'] = True
                message = "Fichier EXE trouvé à l'URL."
                status = "success"
            elif file_name.endswith('.apk'):
                result['apk'] = True
                message = "Fichier APK trouvé à l'URL."
                status = "success"
            elif file_name.endswith('.msi'):
                result['msi'] = True
                message = "Fichier MSI trouvé à l'URL."
                status = "success"
            elif file_name.endswith('.bat'):
                result['bat'] = True
                message = "Fichier BAT trouvé à l'URL."
                status = "success"
            else:
                message = "Le fichier n'est ni un EXE, APK, MSI ou BAT."
                status = "error"
        else:
            message = "L'URL ne pointe pas vers un fichier téléchargeable valide."
            status = "error"

        # Enregistre dans la base de données, avec le domaine
        log = FileLog(
            source="url",
            filename=url.split("/")[-1],
            exe_found=result['exe'],
            apk_found=result['apk'],
            msi_found=result['msi'],
            bat_found=result['bat'],
            domain=domain  # Enregistrement du domaine
        )
        db.session.add(log)
        db.session.commit()

        return render_template('upload_url.html', status=status, message=message)

    except requests.exceptions.RequestException as e:
        message = f"Erreur lors du téléchargement : {str(e)}"
        return render_template('upload_url.html', status="error", message=message)

@app.before_request
def log_incoming_request():
    if request.path.startswith('/static') or request.endpoint == 'socketio.message':
        return  # Ignore les requêtes statiques ou internes
    data = {
        "method": request.method,
        "path": request.path,
        "ip": request.remote_addr,
        "headers": dict(request.headers)
    }
    socketio.emit('http_request', data)


if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080)
