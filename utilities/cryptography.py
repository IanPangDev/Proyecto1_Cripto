from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import hashlib
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from uuid import uuid4

"""
Scritp que se encarga de la parte criptografica
"""

def generate_unique_session_id():
    return str(uuid4())

def sign_message(message, private_key):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(message, signature, public_key):
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("La firma es válida.")
        return True
    except (ValueError, TypeError):
        print("La firma no es válida.")
        return False


def encrypt_symmetric(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def encrypt_asymmetric(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data


def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()


def pbkdf(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def create_keys(secret):
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=secret)
    public_key = key.publickey().export_key()
    return private_key, public_key

