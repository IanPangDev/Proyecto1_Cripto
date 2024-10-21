from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import hashlib
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import base64

"""
Script que se encarga de la parte criptografica
"""

def sign_message(message, private_key):
    """
        Firma un mensaje utilizando la clave privada y el algoritmo SHA256.
        
        :param message: El mensaje a firmar.
        :param private_key: La clave privada para la firma.
        :return: La firma del mensaje.
    """
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(message, signature, public_key):
    """
        Verifica la validez de una firma utilizando la clave pública.
        
        :param message: El mensaje original.
        :param signature: La firma a verificar.
        :param public_key: La clave pública correspondiente.
        :return: True si la firma es válida, False en caso contrario.
    """
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("La firma es válida.")
        return True
    except (ValueError, TypeError):
        print("La firma no es válida.")
        return False


def encrypt_symmetric(message, key):
    """
        Cifra un mensaje utilizando una clave simétrica y el modo GCM.
        
        :param message: El mensaje a cifrar.
        :param key: La clave simétrica para el cifrado.
        :return: El texto cifrado, el tag de autenticación y el nonce.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def decrypt_symmetric(ciphertext, key, tag, nonce):
    """
        Descifra un mensaje cifrado utilizando una clave simétrica y el modo GCM.
        
        :param ciphertext: El texto cifrado.
        :param key: La clave simétrica para el descifrado.
        :param tag: El tag de autenticación.
        :param nonce: El nonce utilizado en el cifrado.
        :return: El mensaje original.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def encrypt_asymmetric(data, public_key):
    """
        Cifra datos utilizando una clave pública y el esquema RSA.
        
        :param data: Los datos a cifrar.
        :param public_key: La clave pública para el cifrado.
        :return: Los datos cifrados.
    """
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def decrypt_asymmetric(encrypted_data, private_key, mode=True):
    """
        Descifra datos cifrados utilizando una clave privada y el esquema RSA.
        
        :param encrypted_data: Los datos cifrados.
        :param private_key: La clave privada para el descifrado.
        :param mode: Determina el algoritmo de hash a usar.
        :return: Los datos descifrados.
    """
    if mode:
        cipher_rsa = PKCS1_OAEP.new(private_key)
    else:
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data


def hash_message(message):
    """
        Calcula el hash de un mensaje utilizando SHA256.
        
        :param message: El mensaje a hashear.
        :return: El hash en formato hexadecimal.
    """
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()


def pbkdf(password, salt, length):
    """
        Deriva una clave a partir de una contraseña utilizando PBKDF2.
        
        :param password: La contraseña a derivar.
        :param salt: La sal para el proceso de derivación.
        :param length: La longitud de la clave derivada.
        :return: La clave derivada.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def create_keys(secret):
    """
        Crea un par de claves RSA (pública y privada).
        
        :param secret: La frase de contraseña para la clave privada.
        :return: La clave privada y la clave pública.
    """
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=secret)
    public_key = key.publickey().export_key()
    return private_key, public_key

def decrypt_message(data, private_key):
    """
        Desencripta un mensaje que incluye una clave simétrica cifrada, 
        texto cifrado, y verifica su firma.
        
        :param data: Un diccionario que contiene todos los datos necesarios para la desencriptación.
        :param private_key: La clave privada para descifrar la clave simétrica.
        :return: El mensaje original si la firma es válida, None en caso contrario.
    """
    encrypted_symmetric_key = base64.b64decode(data['encrypted_symmetric_key'])
    ciphertext = base64.b64decode(data['ciphertext'])
    tag = base64.b64decode(data['tag'])
    nonce = base64.b64decode(data['nonce'])
    message_hash = data['message_hash']
    signature = base64.b64decode(data['signature'])
    public_key =  RSA.import_key(data['public_key'])

    # Desencriptar la clave simétrica usando la clave privada
    symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)

    # Desencriptar el mensaje usando la clave simétrica
    plaintext = decrypt_symmetric(ciphertext, symmetric_key, tag, nonce)

    # Verificar la firma
    is_signature_valid = verify_signature(message_hash, signature, public_key)
    
    if is_signature_valid:
        return plaintext.decode()
    else:
        return None