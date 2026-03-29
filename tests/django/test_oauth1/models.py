from django.contrib.auth.models import User
from django.db.models import CASCADE
from django.db.models import CharField
from django.db.models import ForeignKey
from django.db.models import Model
from django.db.models import TextField

from tests.util import read_file_path


class Client(Model):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, unique=True, db_index=True)
    client_secret = CharField(max_length=48, blank=True)
    default_redirect_uri = TextField(blank=False, default="")

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def get_client_secret(self):
        return self.client_secret

    def get_rsa_public_key(self):
        return read_file_path("rsa_public.pem")


class TokenCredential(Model):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, db_index=True)
    oauth_token = CharField(max_length=84, unique=True, db_index=True)
    oauth_token_secret = CharField(max_length=84)

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret
