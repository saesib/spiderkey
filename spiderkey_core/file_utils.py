import os
import tempfile
from pathlib import Path
from zipfile import ZipFile
import random
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1024 * 1024 * 64  # 64 MB

def encrypt_file(input_path: str, output_file: str, key: bytes):
    input_path = Path(input_path)
    temp_zip_path = Path(tempfile.gettempdir()) / (next(tempfile._get_candidate_names()) + ".zip")

    # Create ZIP from either a single file or a directory
    with ZipFile(temp_zip_path, 'w') as zipf:
        if input_path.is_file():
            zipf.write(input_path, arcname=input_path.name)
        else:
            base_dir = input_path.name
            for root, _, files in os.walk(input_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    arcname = os.path.join(base_dir, os.path.relpath(filepath, input_path))
                    zipf.write(filepath, arcname=arcname)

    aesgcm = AESGCM(key)

    with open(temp_zip_path, 'rb') as fin, open(output_file, 'wb') as fout:
        fout.write(b'SPDRCHNK')  # 8-byte magic header

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            nonce = os.urandom(12)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, associated_data=None)

            fout.write(len(encrypted_chunk).to_bytes(4, 'big'))
            fout.write(nonce)
            fout.write(encrypted_chunk)

    os.unlink(temp_zip_path)

def decrypt_file(input_file: str, output_dir: str, key: bytes):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    temp_zip_path = Path(tempfile.gettempdir()) / (next(tempfile._get_candidate_names()) + ".zip")
    aesgcm = AESGCM(key)

    with open(input_file, 'rb') as fin:
        magic = fin.read(8)
        if magic != b'SPDRCHNK':
            print("Unsupported file format.")
            return

        with open(temp_zip_path, 'wb') as fout:
            while True:
                len_bytes = fin.read(4)
                if not len_bytes:
                    break  # EOF

                chunk_len = int.from_bytes(len_bytes, 'big')
                nonce = fin.read(12)
                chunk_data = fin.read(chunk_len)

                try:
                    decrypted = aesgcm.decrypt(nonce, chunk_data, associated_data=None)
                    fout.write(decrypted)
                except Exception:
                    print("Failed to decrypt a chunk. File may be corrupted or password is incorrect.")
                    return

    try:
        with ZipFile(temp_zip_path, 'r') as zipf:
            zipf.extractall(output_dir)

            # Optional: if there's only one file in zip, move it directly out
            zip_contents = zipf.namelist()
            if len(zip_contents) == 1:
                extracted = output_dir / zip_contents[0]
                new_path = output_dir / Path(zip_contents[0]).name
                extracted.rename(new_path)
                sub_dir = extracted.parent
                if sub_dir != output_dir and sub_dir.exists():
                    try:
                        sub_dir.rmdir()  # Only works if empty
                    except OSError:
                        pass

    except Exception as e:
        print("Failed to unzip decrypted data:", e)
    finally:
        os.unlink(temp_zip_path)

def generate_random_name(length=6):
    while True:
        name = ''.join(random.choices(string.ascii_letters, k=length))
        candidate = Path.cwd() / f"{name}.spdr"
        if not candidate.exists():
            return name
