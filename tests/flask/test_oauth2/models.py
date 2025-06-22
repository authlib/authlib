from flask_sqlalchemy import SQLAlchemy

from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.oidc.core import UserInfo

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password != "wrong"

    def generate_user_info(self, scopes=None):
        profile = {
            "sub": str(self.id),
            "name": self.username,
            "given_name": "Jane",
            "family_name": "Doe",
            "middle_name": "Middle",
            "nickname": "Jany",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "picture": "https://example.com/janedoe/me.jpg",
            "website": "https://example.com",
            "email": "janedoe@example.com",
            "email_verified": True,
            "gender": "female",
            "birthdate": "2000-12-01",
            "zoneinfo": "Europe/Paris",
            "locale": "fr-FR",
            "phone_number": "+1 (425) 555-1212",
            "phone_number_verified": False,
            "address": {
                "formatted": "742 Evergreen Terrace, Springfield",
                "street_address": "742 Evergreen Terrace",
                "locality": "Springfield",
                "region": "Unknown",
                "postal_code": "1245",
                "country": "USA",
            },
            "updated_at": 1745315119,
        }
        return UserInfo(profile)


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)

    @property
    def user(self):
        return db.session.get(User, self.user_id)


class Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def is_refresh_token_active(self):
        return not self.refresh_token_revoked_at

    def get_client(self):
        return db.session.query(Client).filter_by(client_id=self.client_id).one()

    def get_user(self):
        return self.user


class CodeGrantMixin:
    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.get(User, authorization_code.user_id)


def save_authorization_code(code, request):
    client = request.client
    auth_code = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.payload.redirect_uri,
        scope=request.payload.scope,
        nonce=request.payload.data.get("nonce"),
        user_id=request.user.id,
        code_challenge=request.payload.data.get("code_challenge"),
        code_challenge_method=request.payload.data.get("code_challenge_method"),
        acr="urn:mace:incommon:iap:silver",
        amr="pwd otp",
    )
    db.session.add(auth_code)
    db.session.commit()
    return auth_code


def exists_nonce(nonce, request):
    exists = AuthorizationCode.query.filter_by(
        client_id=request.payload.client_id, nonce=nonce
    ).first()
    return bool(exists)
