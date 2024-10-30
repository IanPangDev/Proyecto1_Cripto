from flask import Blueprint, render_template, request, jsonify, redirect, session, flash, send_file
from flask_socketio import join_room, leave_room
import base64
import zipfile
import io
from utilities.cryptography import *
from app.db.DBA import *
from app import socketio
import os

"""
Script que maneja las rutas de la pagina
"""

bp = Blueprint('main', __name__)
sv_private, sv_public = create_keys(getenv("APP_KEY"))
usuarios = {}

@bp.route("/")
def index():
    """
        Maneja la ruta principal.
        
        Redirige a la página de chat si hay una clave simétrica en la sesión;
        de lo contrario, limpia la sesión y muestra la página de login.

        Returns:
            Redirect o rendered template.
    """
    if 'symmetric_key' in session:
        return redirect("/chat")
    else:
        session.clear()
        return render_template("login.html")

@socketio.on('connect')
def handle_connect():
    """
        Conecta por socket al cliente y el servidor.
        
        Le agrega el identificador del socket a la cookie, la agrega al 
        arreglo de usuarios y lo mete a un room para poder comunicarse
        con otros.
    """
    session['unique_session_id'] = request.sid
    usuarios[session['username']] = session['unique_session_id']

    join_room(session['unique_session_id'])

@bp.route("/chat")
def chat():
    """
        Maneja el acceso al chat.
        
        Si no tiene la cookie no lo deja acceder al chat.

        Returns:
            Redirect o rendered template.
    """
    if 'symmetric_key' in session:
        return render_template("index.html",
                                messages=get_messages(session["username"], RSA.import_key(session["private_key"], passphrase=session['password'])),
                                users=usuarios.keys(),
                                username=session["username"])
    else:
        return redirect("/")


@bp.route("/login", methods=["POST"])
def login():
    """
    Maneja el login.
    
    Decifra el contenido cifrado con la llave del server, genera la
    cookie y emite un comunicado a todos los usuarios conectados.

    Returns:
        Retorna un json con informacion de exito o fallo.
    """
    # Si el nombre del usuario ya está en uso
    if request.form["username"] in usuarios.keys():
        return jsonify({'success': False, 'message': 'Error: El nombre de usuario ya está en uso.'})
    elif not('generate_key' in request.form) and (all(f.filename == '' for f in request.files.getlist('keys'))):
        return jsonify({'success': False, 'message': 'Error: No enviaste archivos o no seleccionaste la casilla.'})
    
    # Decifra la información cifrada del usuario
    try:
        username = decrypt_asymmetric(base64.b64decode(request.form['username']),
                                      RSA.import_key(sv_private, passphrase=getenv("APP_KEY")),
                                      False).decode()
        password = decrypt_asymmetric(base64.b64decode(request.form['password']),
                                      RSA.import_key(sv_private, passphrase=getenv("APP_KEY")),
                                      False).decode()
    except Exception as e:
        print("Error de descifrado:", e)
        return jsonify({'success': False, 'message': 'Error: Refresca la página.'})

    # Obtener el valor del "secreto" sin cifrado
    secreto = request.form['secreto']

    # Obtener datos del formulario
    generate_key = request.form['generate_key']
    key_files = request.files.getlist('keys')
    private_key_file = None
    public_key_file = None

    # Verificar archivos PEM
    for file in key_files:
        if file.filename.endswith("private_key.pem"):
            private_key_file = file
        elif file.filename.endswith("public_key.pem"):
            public_key_file = file

    # Validar si se subieron ambas claves o si se seleccionó generar una nueva
    if (private_key_file is None or public_key_file is None) and not generate_key:
        return jsonify({'success': False, 'message': 'Error: No enviaste ambas claves.'})
    
    # Si se subieron archivos
    if generate_key == "false":
        private_key = private_key_file.read()
        public_key = public_key_file.read()
        try:
            RSA.import_key(private_key, passphrase=password)
        except:
            return jsonify({'success': False, 'message': 'Error: La contraseña no coincide con la clave privada.'})
    else:
        # Generación de nuevas claves
        private_key, public_key = create_keys(password)

        # Guardar las claves en "Keys"
        keys_dir = os.path.join(os.getcwd(), 'Keys')
        os.makedirs(keys_dir, exist_ok=True)
        
        with open(os.path.join(keys_dir, f"{username}_private_key.pem"), 'wb') as f:
            f.write(private_key)
        with open(os.path.join(keys_dir, f"{username}_public_key.pem"), 'wb') as f:
            f.write(public_key)

    # Configuración de la sesión
    password = bytes(password, 'utf-8')
    secreto = bytes(secreto, 'utf-8')
    salt = get_random_bytes(16)
    #perdoneme la vida
    symmetric_key = pbkdf(secreto, salt, 32)
    session['private_key'] = private_key
    session['public_key'] = public_key
    session['symmetric_key'] = symmetric_key.hex()
    session['password'] = password
    session['secret'] = secreto  # Guardar el "secreto" en la sesión
    session['username'] = username
    
    # Comunicado para los demás usuarios
    socketio.emit('user_logged_in', {'username': username})
    return jsonify({'success': True})

@bp.route("/download_keys", methods=["POST"])
def download_keys():
    """
        Maneja la descarga de las llaves.
        
        Crea un archivo zip con las llaves del usuario logueado.

        Returns:
            Retorna un archivo zip con las llaves.
    """
    if 'symmetric_key' not in session:
        return redirect("/")
    
    # Buffer de salida para el nuevo archivo
    zip_buffer = io.BytesIO()
    zip_filename = f'{session["username"]}.zip'
    keys_dir = os.path.join(os.getcwd(), 'Keys')

    # Creacion del zip
    with zipfile.ZipFile(zip_buffer, 'w') as zipf:
        private_key_path = os.path.join(keys_dir, f"{session["username"]}_private_key.pem")
        public_key_path = os.path.join(keys_dir, f"{session["username"]}_public_key.pem")
        zipf.write(private_key_path, f"{session["username"]}_private_key.pem")
        zipf.write(public_key_path, f"{session["username"]}_public_key.pem")
    zip_buffer.seek(0)

    return send_file(zip_buffer, as_attachment=True, download_name=zip_filename, mimetype='application/zip')

@socketio.on('send_message')
def send_message(data):
    """
        Maneja el envio de mensajes.
        
        Recibe un json con el mensaje, el remitente y
        el destinatario y lo almacena en una base de datos cifrada.
        Envia un comunicado directo al usuario destinatario.
    """
    if 'symmetric_key' not in session:
        return

    username = data.get("username")
    message = data.get("message")
    recipient = data.get("recipient")
    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'], passphrase=session['password'])
    #no  pudimos, no sabemos javascript
    #public_otro_wey =
    # Cifrado simetrico y firma
    message_hash = hash_message(message)
    signature = sign_message(message_hash, private_key)
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)
    keys_dir = os.path.join(os.getcwd(), 'Keys')
    # Cifrado asimetrico
    with open(os.path.join(keys_dir, f"{recipient}_public_key.pem"), "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

    # Codificar datos binarios a Base64 para serialización en JSON
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    tag_b64 = base64.b64encode(tag).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode()
    ciphertext_me_b64 = base64.b64encode(encrypt_asymmetric(message.encode('utf-8'), RSA.import_key(session['public_key']))).decode()

    message_info = {
        "username": username,
        "recipient": recipient,
        "ciphertext": ciphertext_b64,
        "ciphertext_me": ciphertext_me_b64,
        "tag": tag_b64,
        "nonce": nonce_b64,
        "encrypted_symmetric_key": encrypted_symmetric_key_b64,
        "message_hash": message_hash,
        "signature": base64.b64encode(signature).decode(),
        "public_key": session['public_key'].decode()
    }

    # Almacenamiento de la info en la base de datos
    store_message(message_info)

    # Comunicado al destinatario
    socketio.emit('update_messages', {'message': message, "sender": username}, room=usuarios[recipient])
    return

@bp.route("/logout", methods=['POST'])
def logout():
    """
        Maneja el logout.
        
        Elimina todos los mensajes asociados al usuario,
        emite un comunicado a todos los usuarios conectados y
        borra la cookie.

        Returns:
            Redirige al inicio.
    """
    delete_messages(session["username"])
    socketio.emit('user_logged_out', {'username': session["username"]})
    session.clear()
    return redirect("/")

@socketio.on('disconnect')
def leave():
    """
        Maneja la desconeccion del socket.
        
        Elimina al usuario del conjunto de usuarios conectados
        y lo saca del room para mensajeria.
    """
    del usuarios[session['username']]
    leave_room(room=request.sid)

@bp.route('/public-key', methods=['GET'])
def public_key_endpoint():
    """
        Maneja el envio de la public_key.
        
        Returns:
            Retorna el json con la llave.
    """
    return jsonify({"success":True, "key":sv_public.decode()})