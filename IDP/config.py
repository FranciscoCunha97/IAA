# config.py

import os

class Config:
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class OAuth2Config:
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
