import os
import tempfile
from pathlib import Path
from zipfile import ZipFile
import random
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1024 * 1024 * 64  # 64 MB

def encrypt_file(input_dir: str, output_file: str, key: bytes):
    temp_zip_path = Path(tempfile.gettempdir()) / (next(tempfile._get_candidate_names()) + ".zip")

    # Write zip archive
    with ZipFile(temp_zip_path, 'w') as zipf:
        base_dir = os.path.basename(input_dir.rstrip("/\\"))
        for root, _, files in os.walk(input_dir):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.join(base_dir, os.path.relpath(filepath, input_dir))
                zipf.write(filepath, arcname=arcname)


    # Encrypt the zip file
    with open(temp_zip_path, 'rb') as f:
        data = f.read()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, associated_data=None)

    with open(output_file, 'wb') as f:
        f.write(nonce + encrypted)

    os.unlink(temp_zip_path)

def decrypt_file(input_file: str, output_dir: str, key: bytes):
    from pathlib import Path

    with open(input_file, 'rb') as f:
        nonce = f.read(12)
        ciphertext = f.read()

    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        print("Decryption failed. The resulting file may be corrupted.")
        return

    temp_zip_path = Path(tempfile.gettempdir()) / (next(tempfile._get_candidate_names()) + ".zip")
    with open(temp_zip_path, 'wb') as f:
        f.write(decrypted_data)

    try:
        with ZipFile(temp_zip_path, 'r') as zipf:
            zipf.extractall(output_dir)
    except Exception:
        print("Failed to unzip decrypted data.")
    finally:
        os.unlink(temp_zip_path)

def generate_random_name(length=6):
    while True:
        name = ''.join(random.choices(string.ascii_letters, k=length))
        candidate = Path.cwd() / f"{name}.spdr"
        if not candidate.exists():
            return name