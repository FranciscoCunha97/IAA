# oauth.py

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from models import db, User, OAuth2Client, OAuth2Token, OAuth2AuthorizationCode

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        auth_code = OAuth2AuthorizationCode(
            code=code['code'],
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)

class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        return item

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        db.session.delete(credential)
        db.session.commit()

def query_client(client_id):
    return OAuth2Client.query.filter_by(client_id=client_id).first()

def save_token(token, request):
    if request.user:
        user_id = request.user.id
    else:
        user_id = None
    item = OAuth2Token(
        client_id=request.client.client_id,
        user_id=user_id,
        **token
    )
    db.session.add(item)
    db.session.commit()

authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
authorization.register_grant(AuthorizationCodeGrant)
authorization.register_grant(RefreshTokenGrant)
