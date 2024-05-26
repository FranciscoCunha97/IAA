from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin, OAuth2AuthorizationCodeMixin

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    pin = db.Column(db.String(150), nullable=True)  # PIN criptografado para serviços de grau alto
    citizen_card = db.Column(db.String(50), unique=True, nullable=True)  # Cartão de Cidadão

    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

    def set_pin(self, pin):
        self.pin = generate_password_hash(pin)
    
    def check_pin(self, pin):
        return check_password_hash(self.pin, pin)

class OAuth2Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    criticality_level = db.Column(db.String(20), nullable=False, default='low')  # 'low', 'medium', 'high'

class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

class OAuth2Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
