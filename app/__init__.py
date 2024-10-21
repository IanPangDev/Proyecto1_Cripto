from flask import Flask
from flask_session import Session
from flask_socketio import SocketIO
from os import getenv

"""
Script que crea la app con su configuracion
"""
socketio = SocketIO()

def create_app():
    global socketio

    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.secret_key = getenv("APP_KEY")
    socketio.init_app(app)
    Session(app)
    
    with app.app_context():
        from .routes import bp as main_routes
        app.register_blueprint(main_routes)

    return app, socketio