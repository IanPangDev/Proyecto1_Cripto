from app import create_app
from dotenv import load_dotenv
"""
Script que inicializa la pagina
"""

app, socketio = create_app()
load_dotenv()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8000)