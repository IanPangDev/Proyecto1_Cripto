import os
from re import search, findall

"""
Scripts con algunas funciones extras
"""

def get_users(username=''):
    session_dir = 'flask_session'
    usuarios = []
    for filename in os.listdir(session_dir):
        file_path = os.path.join(session_dir, filename)
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 53:
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].rstrip()
                        user_re = search('username', last_line)
                        next_user = findall(r"\w+", last_line[user_re.end():-2])[0]
                        if username != next_user:
                            usuarios.append(next_user)
            except Exception as e:
                print(f"Error al leer {filename}: {e}")
                
    return usuarios