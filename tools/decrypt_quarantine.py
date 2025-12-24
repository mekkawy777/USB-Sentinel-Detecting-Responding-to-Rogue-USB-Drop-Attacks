import os
import sys
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
KEY_FILE = os.path.join(BASE_DIR, "sentinel.key")

if not os.path.exists(KEY_FILE):
    print("[-] Encryption key not found")
    sys.exit(1)

cipher = Fernet(open(KEY_FILE, "rb").read())

def decrypt_file(enc_path, out_path):
    with open(enc_path, "rb") as f:
        data = f.read()

    plain = cipher.decrypt(data)

    with open(out_path, "wb") as f:
        f.write(plain)

    print(f"[+] Decrypted → {out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decrypt_quarantine.py <file.enc> <output>")
        sys.exit(1)

    decrypt_file(sys.argv[1], sys.argv[2])
