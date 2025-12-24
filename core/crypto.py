import os
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
KEY_FILE = os.path.join(BASE_DIR, "sentinel.key")

def load_cipher():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

CIPHER = load_cipher()
