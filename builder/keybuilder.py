import os
import base64
import hashlib
import tempfile
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from spiderkey_core.crypto_utils import derive_key

TEMPLATE_PATH = "templates/spiderkey_template.py"

def encrypt_key(aes_key: bytes, kek: bytes) -> bytes:
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, aes_key, associated_data=None)
    return nonce + encrypted  # Include nonce for decryption

def create_spiderkey(name: str, password: str, seed: str = None):
    # 1. Generate or derive salt
    salt = os.urandom(16)

    # 2. Generate AES key
    if seed:
        # If a seed is provided, use it to generate a consistent AES key
        aes_key = hashlib.sha256((seed + password).encode()).digest()[:32]
    else:
        # Otherwise, generate a random AES key
        aes_key = os.urandom(32)

    # 3. Derive KEK from password + salt
    kek = derive_key(password, salt)

    # 4. Encrypt the AES key
    encrypted_key = encrypt_key(aes_key, kek)

    # 5. Encode for embedding
    salt_b64 = base64.b64encode(salt).decode()
    enc_key_b64 = base64.b64encode(encrypted_key).decode()

    # 6. Read the SpiderKey template
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()

    # 7. Inject constants
    filled_code = (
        template
        .replace("{{SALT}}", salt_b64)
        .replace("{{ENCRYPTED_KEY}}", enc_key_b64)
    )

    # 8. Write to temp file
    temp_py = Path(tempfile.gettempdir()) / f"{name}.py"
    with open(temp_py, "w", encoding="utf-8") as f:
        f.write(filled_code)


    output_dir = Path("spiderkeys")
    output_dir.mkdir(exist_ok=True)

    existing_exe = output_dir / f"{name}.exe"
    if existing_exe.exists():
        existing_exe.unlink()
    # 9. Compile to binary using PyInstaller
    subprocess.run([
        "pyinstaller",
        "--onefile",
        "--name", name,
        "--distpath", str(output_dir),
        "--path", ".",
        "--hidden-import=argon2.low_level",  # needed for key derivation on  linux based systems
        "--hidden-import=spiderkey_core.crypto_utils",
        "--hidden-import=spiderkey_core.file_utils",
        "--hidden-import=spiderkey_core.loader",
        "--hidden-import=spiderkey_core.shredder",
        str(temp_py)
    ])

    print(f"✅ SpiderKey '{name}' built successfully.")

    # Cleanup: remove .spec and build files (optional)
    try:
        os.remove(f"{name}.spec")
        import shutil
        shutil.rmtree("build")
        shutil.rmtree("__pycache__")
    except Exception:
        pass
