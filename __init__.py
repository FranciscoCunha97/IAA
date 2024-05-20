from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_oauth2 import AuthorizationServer
import os

db = SQLAlchemy()
authorization = AuthorizationServer()

def create_app():

    secret_key = os.urandom(24).hex()
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://database.db'
    app.config['SECRET_KEY'] = secret_key

    db.init_app(app)
    authorization.init_app(app)

    with app.app_context():
        from . import routes
        db.create_all()

    return app
