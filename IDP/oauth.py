import time
import secrets
from models import add_oauth2_authorization_code, get_oauth2_authorization_code, add_oauth2_token, get_oauth2_token, get_oauth2_client, introspect_token, revoke_token

def generate_authorization_code(user_id, client_id, redirect_uri):
    code = secrets.token_urlsafe(40)
    expires_at = int(time.time()) + 600  # 10 minutos
    add_oauth2_authorization_code(user_id, client_id, code, redirect_uri, expires_at)
    return code

def validate_authorization_code(code):
    authorization_code = get_oauth2_authorization_code(code)
    if authorization_code and authorization_code['expires_at'] > int(time.time()):
        return authorization_code
    return None

def generate_token(user_id, client_id):
    access_token = secrets.token_urlsafe(40)
    refresh_token = secrets.token_urlsafe(40)
    expires_at = int(time.time()) + 3600  # 1 hora
    add_oauth2_token(user_id, client_id, access_token, refresh_token, expires_at)
    return access_token, refresh_token, expires_at

def validate_token(access_token):
    token = get_oauth2_token(access_token)
    if token and token['expires_at'] > int(time.time()) and token['revoked'] == 0:
        return token
    return None
