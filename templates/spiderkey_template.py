"""
SpiderKey Program Template
This file will be compiled into a standalone key program.
"""

import os
import sys
import base64
import shutil
import tempfile
import random
import string
from zipfile import ZipFile
from getpass import getpass
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- BEGIN EMBEDDED CONSTANTS ---
ENCRYPTED_AES_KEY_B64 = "{{ENCRYPTED_KEY}}"
SALT_B64 = "{{SALT}}"
# --- END EMBEDDED CONSTANTS ---

def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=4,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.I,
    )

def decrypt_key(encrypted_key: bytes, kek: bytes) -> bytes:
    nonce = encrypted_key[:12]
    tag = encrypted_key[-16:]
    ciphertext = encrypted_key[12:-16]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)

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

def main():
    spider_art = r'''
###############################################################
#       /      \         __      _\( )/_                      #
#    \  \  ,,  /  /   | /  \ |    /(O)\                       #
#     '-.`\()/`.-'   \_\\  //_/_.._     _\(o)/_  //  \\       #
#    .--_'(  )'_--.   .'/()\'. .'    '.  /(_)\  _\\()//_      #
#   / /` /`""`\ `\ \   \\  // /   __   \       / //  \\ \     #
#    |  |  ><  |  |         , |   ><   |  ,     | \__/ |      #
#    \  \      /  /        . \ \      /  / .                  #
#    _   '.__.'    _\(O)/_ \_'--`(  )'--'_/     __            #
# _\( )/_           /(_)\    .--'/()\'--.    | /  \ |         #
#  /(O)\  //  \\           _/  /` '' `\  \  \_\\  //_/_       #
#        _\\()//_   _\(_)/_   |        |      //()\\          #
#       / //  \\ \   /(o)\     \      /       \\  //          #
#        | \__/ |                                             #
###############################################################
    '''

    print(spider_art)
    print("Welcome to your SpiderKey. Type 'help' for available commands.")

    while True:
        command = input("> ").strip()

        if command.lower() in ["q", "quit", "exit", "logout"]:
            print("Goodbye.")
            break

        elif command.lower() == "help":
            print("""
Available commands:
  e <folder>         Encrypt a folder
  d <file.spdr>      Decrypt an encrypted file
  help               Show this help message
  quit / q / exit    Exit the program
""")

        elif command.startswith("e "):
            parts = command.split(maxsplit=1)
            input_dir = parts[1]
            if not os.path.isdir(input_dir):
                print(f"Folder '{input_dir}' does not exist.")
                continue

            raw_name = input("Output file name (leave blank for random): ").strip()
            if not raw_name:
                raw_name = generate_random_name()
                print(f"Generated name: {raw_name}")
            output_name = f"{raw_name}.spdr"

            save_dir = input("Save location (leave blank or '.' for current directory): ").strip()
            if not save_dir:
                save_dir = '.'
            if not os.path.isdir(save_dir):
                print(f"Directory '{save_dir}' does not exist.")
                continue

            output_path = Path(save_dir) / output_name
            if output_path.exists():
                print(f"File '{output_path}' already exists.")
                continue

            password = getpass("Enter your password: ")
            salt = base64.b64decode(SALT_B64)
            encrypted_key = base64.b64decode(ENCRYPTED_AES_KEY_B64)
            kek = derive_key(password, salt)
            aes_key = decrypt_key(encrypted_key, kek)
            encrypt_file(input_dir, str(output_path), aes_key)
            print(f"Encrypted to {output_path}")

        elif command.startswith("d "):
            parts = command.split(maxsplit=1)
            input_file = parts[1]
            if not os.path.isfile(input_file):
                print(f"File '{input_file}' does not exist.")
                continue
            
            extract_to = Path(input_file).parent  # current directory or same location as the encrypted file

            password = getpass("Enter your password: ")
            salt = base64.b64decode(SALT_B64)
            encrypted_key = base64.b64decode(ENCRYPTED_AES_KEY_B64)
            kek = derive_key(password, salt)
            aes_key = decrypt_key(encrypted_key, kek)

            try:
                decrypt_file(input_file, extract_to, aes_key)
                print(f"Decrypted contents extracted to: {extract_to.resolve()}")
            except Exception as e:
                print("Decryption failed:", e)

        elif command == "e" or command == "d":
            print("Missing argument. Use 'e <folder>' or 'd <file>'.")

        else:
            print("Unknown command. Type 'help' to see available commands.")

if __name__ == "__main__":
    main()