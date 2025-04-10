import os
import mimetypes

def detect_file_type(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == '.exe':
        return "Fichier exécutable Windows (.exe)"
    elif ext == '.apk':
        return "Fichier Android (.apk)"

    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type:
        if "application/vnd.android.package-archive" in mime_type:
            return "APK détecté par MIME type"
        elif "application/x-msdownload" in mime_type:
            return "EXE détecté par MIME type"

    with open(file_path, "rb") as f:
        header = f.read(4)
        if header.startswith(b'MZ'):
            return "Fichier .exe détecté par signature"
        elif header.startswith(b'PK'):
            return "Fichier .apk (probable, archive zip)"

    return "Fichier non reconnu"
