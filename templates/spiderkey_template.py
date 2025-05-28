"""
SpiderKey Program Template
This file will be compiled into a standalone key program.
"""

from spiderkey_core.crypto_utils import derive_key, decrypt_key
from spiderkey_core.file_utils import encrypt_file, decrypt_file, generate_random_name
from spiderkey_core.loader import Loader

import os
import base64
from getpass import getpass
from pathlib import Path

# --- BEGIN EMBEDDED CONSTANTS ---
ENCRYPTED_AES_KEY_B64 = "{{ENCRYPTED_KEY}}"
SALT_B64 = "{{SALT}}"
# --- END EMBEDDED CONSTANTS ---

def prompt_password_and_decrypt_key() -> bytes | None:
    salt = base64.b64decode(SALT_B64)
    encrypted_key = base64.b64decode(ENCRYPTED_AES_KEY_B64)

    for attempt in range(2): # Allow 2 attempts before returning to main menu
        password = getpass("Enter your password: ")
        kek = derive_key(password, salt)
        try:
            return decrypt_key(encrypted_key, kek)
        except Exception:
            print("Wrong password.")
    print("Too many failed attempts. Returning to menu.")
    return None


def main():
    spider_art = r'''
###############################################################
#                                                             #    
#       /      \                 _\( )/_                      #
#    \  \  ,,  /  /               /(O)\                       #
#     '-.`\()/`.-'                            _.._   _\(o)/_  #
#    .--_'(  )'_--.                         .'    '.  /(_)\   #
#   / /` /`""`\ `\ \                       /   __   \         # 
#    |  |  ><  |  |    | /  \ |          , |   ><   |  ,      #
#    \  \      /  /   \_\\  //_/        . \ \      /  / .     #             
#        '.__.'         //()\\          \_'--`(  )'--'_/      #
#                       \\  //            .--'/()\'--.        # 
#                 .--.                  _/  /` '' `\  \_      #
#     _\( )/_    /.-. '----------.         |        |         #
#      /(O)\     \'-' .--"--""-"-'          \      /          # 
#                 '--'                                        #
###############################################################
    '''
    print("\033[31m", end="")  # red text
    print(spider_art)
    print("Welcome to your SpiderKey. Type 'help' for available commands.")

    while True:
        command = input("> ").strip()

        if command.lower() in ["q", "quit", "exit", "logout"]:
            print("Goodbye.")
            print("\033[0m", end="")  # Reset text color
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

            aes_key = prompt_password_and_decrypt_key()
            if aes_key is None:
                continue  # Skip encryption if key couldn't be decrypted after retries
            loader = Loader("Encrypting")
            loader.start()
            try:                
                encrypt_file(input_dir, str(output_path), aes_key)
                loader.stop()
                print(f"Encrypted to {output_path}")
            except Exception as e:
                loader.stop()
                print(f"Encryption failed: {e}")

        elif command.startswith("d "):
            parts = command.split(maxsplit=1)
            input_file = parts[1]
            if not os.path.isfile(input_file):
                print(f"File '{input_file}' does not exist.")
                continue
            
            extract_to = Path(input_file).parent  # current directory or same location as the encrypted file
            aes_key = prompt_password_and_decrypt_key()
            if aes_key is None:
                continue  # Skip decryption if key couldn't be decrypted after retries
            loader = Loader("Decrypting")
            loader.start()
            try:
                decrypt_file(input_file, extract_to, aes_key)
                loader.stop()
                print(f"Decrypted contents extracted to: {extract_to.resolve()}")
            except Exception as e:
                loader.stop()
                print("Decryption failed:", e)

        elif command == "e" or command == "d":
            print("Missing argument. Use 'e <folder>' or 'd <file>'.")

        else:
            print("Unknown command. Type 'help' to see available commands.")

if __name__ == "__main__":
    main()