from flask import Blueprint, render_template, request, jsonify, redirect, session
import base64
import os
from utilities.cryptography import *

bp = Blueprint('main', __name__)

@bp.route("/")
def index():
    if 'symmetric_key' in session:
        print("Redireccionando al chat...")
        return redirect("/chat")
    else:
        print("Mostrando página de login...")
        return render_template("login.html")


@bp.route("/chat")
def chat():
    return render_template("index.html")
    # if 'symmetric_key' in session:
    #     print("Chat iniciado con claves en sesión.")
    #     return render_template("index.html",
    #                             messages=session.get('messages', []))
    # else:
    #     print("No hay sesión iniciada, redirigiendo al inicio.")
    #     return redirect("/")


@bp.route("/login", methods=["POST"])
def login():
    session.clear()
    username = request.form["username"]
    password = request.form["password"]
    key_dir = os.path.join("app", "keys")
    private_key_path = os.path.join(key_dir, username + "private.pem")
    public_key_path = os.path.join(key_dir, username + "public.pem")
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        create_keys(password, private_key_path, public_key_path)

    with open(private_key_path, "rb") as f:
        private_key_data = f.read()
    private_key = RSA.import_key(private_key_data, passphrase=password)

    with open(public_key_path, "rb") as f:
        public_key_data = f.read()
    public_key = RSA.import_key(public_key_data)

    password = bytes(password, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf(password, salt, 32)

    session['unique_session_id'] = generate_unique_session_id()
    session['private_key'] = private_key.export_key().decode()
    session['public_key'] = public_key.export_key().decode()
    session['symmetric_key'] = symmetric_key.hex()
    session['messages'] = []
    session['username'] = username

    print("Usuario logueado, sesión iniciada con claves cargadas.")
    # Imprimir información en la terminal
    print("Clave privada RSA:")
    print(private_key.export_key().decode())
    print("\nClave pública RSA:")
    print(public_key.export_key().decode())
    print("\nSalt generado:", salt.hex())
    print("Clave simétrica derivada:", symmetric_key.hex())

    return redirect("/chat")


@bp.route("/send_message", methods=["POST"])
def send_message():
    if 'symmetric_key' not in session:
        return jsonify({"error": "Debes iniciar sesión para enviar mensajes."}), 403

    username = request.form["username"]
    message = request.form["message"]
    recipient = request.form["recipient"]
    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'].encode())

    message_hash = hash_message(message)
    signature = sign_message(message_hash, private_key)
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)
    public_key = RSA.import_key(session['public_key'].encode())
    encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

    # Codificar datos binarios a Base64 para serialización en JSON
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    tag_b64 = base64.b64encode(tag).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode()

    message_info = {
        "username": username,
        "recipient": recipient,
        "message": message,
        "ciphertext": ciphertext_b64,
        "tag": tag_b64,
        "nonce": nonce_b64,
        "encrypted_symmetric_key": encrypted_symmetric_key_b64,
        "message_hash": message_hash,
        "signature": base64.b64encode(signature).decode()
    }
    session['messages'].append(message_info)

    print("\nMensaje cifrado RSA:", encrypted_symmetric_key_b64)
    print("Mensaje descifrado:", message)
    print("Tag:", tag_b64)
    print("Nonce (IV):", nonce_b64)
    print("Mensaje integro")
    is_signature_valid = verify_signature(message_hash, signature, public_key)
    print(f"Mensaje de {username} cifrado y enviado a {recipient}.")
    return jsonify({"username": username, "message": message})

@bp.route("/get_messages")
def get_messages():
    print("Recuperando mensajes de la sesión...")
    messages = session.get('messages', [])
    return jsonify({"messages": messages})

@bp.route("/logout", methods=['POST'])
def logout():
    print("Cerrando sesión y limpiando datos...")
    session.clear()
    return redirect("/")