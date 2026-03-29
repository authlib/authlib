import time

from django.contrib.auth.models import User
from django.db.models import CASCADE
from django.db.models import CharField
from django.db.models import ForeignKey
from django.db.models import IntegerField
from django.db.models import Model
from django.db.models import TextField

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import AuthorizationCodeMixin
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oauth2.rfc6749.util import list_to_scope
from authlib.oauth2.rfc6749.util import scope_to_list


def now_timestamp():
    return int(time.time())


class Client(Model, ClientMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, unique=True, db_index=True)
    client_secret = CharField(max_length=48, blank=True)
    redirect_uris = TextField(default="")
    default_redirect_uri = TextField(blank=False, default="")
    scope = TextField(default="")
    response_type = TextField(default="")
    grant_type = TextField(default="")
    token_endpoint_auth_method = CharField(max_length=120, default="")

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(scope_to_list(self.scope))
        return list_to_scope([s for s in scope.split() if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        if redirect_uri == self.default_redirect_uri:
            return True
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return self.token_endpoint_auth_method == method
        return True

    def check_response_type(self, response_type):
        allowed = self.response_type.split()
        return response_type in allowed

    def check_grant_type(self, grant_type):
        allowed = self.grant_type.split()
        return grant_type in allowed


class OAuth2Token(Model, TokenMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, db_index=True)
    token_type = CharField(max_length=40)
    access_token = CharField(max_length=255, unique=True, null=False)
    refresh_token = CharField(max_length=255, db_index=True)
    scope = TextField(default="")

    issued_at = IntegerField(null=False, default=now_timestamp)
    expires_in = IntegerField(null=False, default=0)
    access_token_revoked_at = IntegerField(default=0)
    refresh_token_revoked_at = IntegerField(default=0)

    def check_client(self, client):
        return self.client_id == client.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_revoked(self):
        return self.access_token_revoked_at or self.refresh_token_revoked_at

    def is_expired(self):
        if not self.expires_in:
            return False

        expires_at = self.issued_at + self.expires_in
        return expires_at < time.time()

    def is_refresh_token_active(self):
        return not self.refresh_token_revoked_at


class OAuth2Code(Model, AuthorizationCodeMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, db_index=True)
    code = CharField(max_length=120, unique=True, null=False)
    redirect_uri = TextField(default="", null=True)
    response_type = TextField(default="")
    scope = TextField(default="", null=True)
    auth_time = IntegerField(null=False, default=now_timestamp)

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope or ""

    def get_auth_time(self):
        return self.auth_time


class CodeGrantMixin:
    def query_authorization_code(self, code, client):
        try:
            item = OAuth2Code.objects.get(code=code, client_id=client.client_id)
        except OAuth2Code.DoesNotExist:
            return None

        if not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


def generate_authorization_code(client, grant_user, request, **extra):
    code = generate_token(48)
    item = OAuth2Code(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.payload.redirect_uri,
        response_type=request.payload.response_type,
        scope=request.payload.scope,
        user=grant_user,
        **extra,
    )
    item.save()
    return code
