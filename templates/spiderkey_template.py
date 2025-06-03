"""
SpiderKey Program Template
This file will be compiled into a standalone key program.
"""

from spiderkey_core.crypto_utils import derive_key, decrypt_key
from spiderkey_core.file_utils import encrypt_file, decrypt_file, generate_random_name
from spiderkey_core.loader import Loader
from spiderkey_core.shredder import Shredder


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

def shred(file_or_folder: str):
    shredder = Shredder()
    loader = Loader("Shredding")
    loader.start()

    try:
        if os.path.isfile(file_or_folder):
            shredder.shred_file(file_or_folder)
        else:
            shredder.shred_directory(file_or_folder)
        loader.stop()
        print(f"'{file_or_folder}' has been securely deleted.")
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as e:
        loader.stop()
        print(str(e))
    except Exception as e:
        loader.stop()
        print(f"Shredding failed: {e}")

def path_completer(text, state):
    matches = glob.glob(text + '*')
    if state < len(matches):
        return matches[state]
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

    # Main loop for command input
    while True:
        command = input("> ").strip()

        if command.lower() in ["q", "quit", "exit", "logout"]:
            print("Goodbye.")
            print("\033[0m", end="")  # Reset text color
            break

        elif command.lower() == "help":
            print("""
Available commands:
  e <file|folder>       Encrypt a folder
  d <file.spdr>         Decrypt an encrypted file
  s <file|folder>       Securely delete a file or folder
  cd <path>             Change working directory (supports '/' and '\\')
  pwd                   Show current working directory
  ls                    List contents of current directory
  clear                 Clear the screen and redraw SpiderKey banner
  help                  Show this help message
  quit / q / exit       Exit the program
""")

        elif command.startswith("e "):
            parts = command.split(maxsplit=1)
            input_dir = parts[1].strip('\'"')
            if not os.path.exists(input_dir):
                print(f"File or folder '{input_dir}' does not exist.")
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
                while True:
                    choice = input("Do you want to shred the decrypted file? (y/n): ").strip().lower()
                    if choice == 'y':
                        shred(input_dir)
                        break
                    elif choice == 'n':
                        print("Decrypted file retained.")
                        break
                    else:
                        print("Invalid choice. Please enter 'y' or 'n'.")
                        continue
            except Exception as e:
                loader.stop()
                print(f"Encryption failed: {e}")
            

        elif command.startswith("d "):
            parts = command.split(maxsplit=1)
            input_file = parts[1]
            # Try the exact filename first
            if not os.path.isfile(input_file):
                # Try adding .spdr if not found
                if os.path.isfile(input_file + ".spdr"):
                    input_file += ".spdr"
                    print(f"Using file: {input_file}")
                else:
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
                while True:
                    choice = input("Do you want to shred the encrypted file? (y/n): ").strip().lower()
                    if choice == 'y':
                        shred(input_file)
                        break
                    elif choice == 'n':
                        print("Encrypted file retained.")
                        break
                    else:
                        print("Invalid choice. Please enter 'y' or 'n'.")
                        continue
            except Exception as e:
                loader.stop()
                print("Decryption failed:", e)
        
        elif command.startswith("s "):
            parts = command.split(maxsplit=1)
            if len(parts) < 2:
                print("Missing argument. Use 'shred <file>' or 'shred <folder>'.")
                continue
            
            target = parts[1]

            if not os.path.exists(target):
                print(f"'{target}' does not exist.")
                continue
            
            print("WARNING: Shredding will permanently destroy the file or folder and it cannot be recovered.")
            confirm = input(f"Are you sure you want to shred '{target}'? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Shredding cancelled.")
                continue
            
            shred(target)
        elif command.startswith("cd "):
            parts = command.split(maxsplit=1)
            target_dir = parts[1].strip('"\'')
            try:
                os.chdir(target_dir)
                print(f"Changed directory to: {os.getcwd()}")
            except Exception as e:
                print(f"cd failed: {e}")

        elif command == "pwd":
            print(os.getcwd())

        elif command == "ls":
            try:
                for item in os.listdir():
                    print(item)
            except Exception as e:
                print(f"ls failed: {e}")
        
        elif command == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            print("\033[31m", end="")  # red text
            print(spider_art)


        elif command == "e" or command == "d":
            print("Missing argument. Use 'e <folder>' or 'd <file>'.")

        else:
            print("Unknown command. Type 'help' to see available commands.")

if __name__ == "__main__":
    main()