from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_oauth2 import AuthorizationServer

db = SQLAlchemy()
authorization = AuthorizationServer()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://database.db'
    app.config['SECRET_KEY'] = ''

    db.init_app(app)
    authorization.init_app(app)

    with app.app_context():
        from . import routes
        db.create_all()

    return app
