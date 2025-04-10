from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Création de l'objet db qui sera utilisé pour interagir avec la base de données
db = SQLAlchemy()

class FileLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(255))  # La source du fichier (upload, url)
    filename = db.Column(db.String(255))  # Le nom du fichier téléchargé
    exe_found = db.Column(db.Boolean, default=False)  # Indique si un fichier .exe a été trouvé
    apk_found = db.Column(db.Boolean, default=False)  # Indique si un fichier .apk a été trouvé
    msi_found = db.Column(db.Boolean, default=False)  # Indique si un fichier .msi a été trouvé
    bat_found = db.Column(db.Boolean, default=False)  # Indique si un fichier .bat a été trouvé
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp de l'enregistrement
    domain_valid = db.Column(db.Boolean, default=False)  # Indique si le domaine est valide
    domain = db.Column(db.String(255))  # Enregistre le nom du domaine pour l'URL

    def __repr__(self):
        return f"<FileLog {self.filename} - {self.timestamp}>"
