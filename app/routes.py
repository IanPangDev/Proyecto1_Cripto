from flask import Blueprint, render_template, request, jsonify, redirect, session, flash
import base64
from utilities.cryptography import *
from utilities.utilities import *

bp = Blueprint('main', __name__)

@bp.route("/")
def index():
    if 'symmetric_key' in session:
        print("Redireccionando al chat...")
        return redirect("/chat")
    else:
        session.clear()
        print("Mostrando página de login...")
        return render_template("login.html")


@bp.route("/chat")
def chat():
    if 'symmetric_key' in session:
        print("Chat iniciado con claves en sesión.")
        return render_template("index.html",
                                messages=session.get('messages'), users=get_users(session['username']))
    else:
        print("No hay sesión iniciada, redirigiendo al inicio.")
        return redirect("/")


@bp.route("/login", methods=["POST"])
def login():
    if request.form["username"] in get_users():
        flash('Error: El nombre de usuario ya está en uso.')
        return render_template("login.html")

    username = request.form["username"]
    password = request.form["password"]
    generate_key = 'generate_key' in request.form
    key_files = request.files.getlist('keys')
    private_key_file = None
    public_key_file = None
    for file in key_files:
        if file.filename.endswith("private_key.pem"):
            private_key_file = file
        elif file.filename.endswith("public_key.pem"):
            public_key_file = file

    # Verificar si el usuario subió una clave privada o eligió generar una nueva
    if private_key_file and private_key_file.filename != '':
        private_key = private_key_file.read()
        public_key = public_key_file.read()
        flash('Clave privada y pública cargadas correctamente.')
    elif generate_key:
        # Si el usuario elige generar una nueva clave
        private_key, public_key = create_keys(password)

        # Guardar la clave privada en la carpeta "Keys"
        keys_dir = os.path.join(os.getcwd(), 'Keys')
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
        private_key_path = os.path.join(keys_dir, f"{username}_private_key.pem")
        with open(private_key_path, 'wb') as f:
            f.write(private_key)
        public_key_path = os.path.join(keys_dir, f"{username}_public_key.pem")
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        flash('Nueva clave privada generada.')
    else:
        flash('Error: Debes subir una clave privada o generar una nueva.')
        return redirect("/login")
    password = bytes(password, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf(password, salt, 32)
    session['unique_session_id'] = generate_unique_session_id()
    session['private_key'] = private_key
    session['public_key'] = public_key
    session['symmetric_key'] = symmetric_key.hex()
    session['password'] = password
    session['messages'] = []
    session['username'] = username
    print("Usuario logueado, sesión iniciada con claves cargadas.")
    # Imprimir información en la terminal
    print("Clave privada RSA:")
    print(private_key)
    print("\nClave pública RSA:")
    print(public_key)
    print("\nSalt generado:", salt.hex())
    print("Clave simétrica derivada:", symmetric_key.hex())
    return redirect("/chat")

@bp.route("/send_message", methods=["POST"])
def send_message():
    if 'symmetric_key' not in session:
        return jsonify({"error": "Debes iniciar sesión para enviar mensajes."}), 403

    print("DATA: ", request.json)
    username = request.json["username"]
    message = request.json["message"]
    recipient = request.json["recipient"]
    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'], passphrase=session['password'])

    message_hash = hash_message(message)
    signature = sign_message(message_hash, private_key)
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)
    public_key = RSA.import_key(session['public_key'].decode())
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