# app.py

from flask import Flask
from config import Config, OAuth2Config
from models import db
from routes import bp as main_bp
from flask_session import Session

app = Flask(__name__)
app.config.from_object(Config)
app.config.from_object(OAuth2Config)
app.config['SESSION_TYPE'] = 'filesystem'

db.init_app(app)
Session(app)

with app.app_context():
    db.create_all()

app.register_blueprint(main_bp)

if __name__ == '__main__':
    app.run(debug=True)
