from app import create_app
from dotenv import load_dotenv

"""
Script que inicializa la pagina
"""

app = create_app()
load_dotenv()

if __name__ == '__main__':
    app.run(debug=True, port=8000)