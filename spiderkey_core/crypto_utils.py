import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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