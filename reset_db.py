import os
from app import db, app, add_user

db_file = 'logs.db'

# Supprimer l'ancienne base
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"[✔] Ancienne base '{db_file}' supprimée.")
else:
    print(f"[ℹ] Aucun fichier '{db_file}' trouvé à supprimer.")

# Exécuter tout dans le contexte Flask
with app.app_context():
    db.create_all()
    print("[✔] Nouvelle base de données créée.")

    # Ajouter un utilisateur admin si non existant
    add_user('admin', 'password123', 'admin@example.com', 'OpenAI', 'admin')
    add_user('jean', 'monmotdepasse', 'jean@example.com', 'Apple', 'user')
    print("[✔] Utilisateurs ajoutés (si inexistants).")

