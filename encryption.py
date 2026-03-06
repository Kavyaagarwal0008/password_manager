import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def encrypt_password(password, master_password):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)

    aes = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(nonce, password.encode(), None)

    return base64.b64encode(salt + nonce + ciphertext).decode()


def decrypt_password(encrypted, master_password):
    data = base64.b64decode(encrypted.encode())

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    key = derive_key(master_password, salt)

    aes = AESGCM(key)

    return aes.decrypt(nonce, ciphertext, None).decode()