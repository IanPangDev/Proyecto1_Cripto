from flask import Flask
from flask_session import Session
from os import urandom

"""
Scritp que crea la app con su configuracion
"""

def create_app():
    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.secret_key = urandom(24)
    Session(app)
    
    with app.app_context():
        from .routes import bp as main_routes
        app.register_blueprint(main_routes)

    return app