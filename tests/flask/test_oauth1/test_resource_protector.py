import time

from flask import json

from authlib.common.urls import add_params_to_uri
from authlib.oauth1.rfc5849 import signature
from tests.util import read_file_path

from .oauth1_server import Client
from .oauth1_server import TestCase
from .oauth1_server import TokenCredential
from .oauth1_server import User
from .oauth1_server import create_resource_server
from .oauth1_server import db


class ResourceCacheTest(TestCase):
    USE_CACHE = True

    def prepare_data(self):
        create_resource_server(self.app, self.USE_CACHE, self.USE_CACHE)
        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id="client",
            client_secret="secret",
            default_redirect_uri="https://a.b",
        )
        db.session.add(client)
        db.session.commit()

        tok = TokenCredential(
            user_id=user.id,
            client_id=client.client_id,
            oauth_token="valid-token",
            oauth_token_secret="valid-token-secret",
        )
        db.session.add(tok)
        db.session.commit()

    def test_invalid_request_parameters(self):
        self.prepare_data()
        url = "/user"

        # case 1
        rv = self.client.get(url)
        data = json.loads(rv.data)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_consumer_key" in data["error_description"]

        # case 2
        rv = self.client.get(add_params_to_uri(url, {"oauth_consumer_key": "a"}))
        data = json.loads(rv.data)
        assert data["error"] == "invalid_client"

        # case 3
        rv = self.client.get(add_params_to_uri(url, {"oauth_consumer_key": "client"}))
        data = json.loads(rv.data)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_token" in data["error_description"]

        # case 4
        rv = self.client.get(
            add_params_to_uri(url, {"oauth_consumer_key": "client", "oauth_token": "a"})
        )
        data = json.loads(rv.data)
        assert data["error"] == "invalid_token"

        # case 5
        rv = self.client.get(
            add_params_to_uri(
                url, {"oauth_consumer_key": "client", "oauth_token": "valid-token"}
            )
        )
        data = json.loads(rv.data)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_timestamp" in data["error_description"]

    def test_plaintext_signature(self):
        self.prepare_data()
        url = "/user"

        # case 1: success
        auth_header = (
            'OAuth oauth_consumer_key="client",'
            'oauth_signature_method="PLAINTEXT",'
            'oauth_token="valid-token",'
            'oauth_signature="secret&valid-token-secret"'
        )
        headers = {"Authorization": auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert "username" in data

        # case 2: invalid signature
        auth_header = auth_header.replace("valid-token-secret", "invalid")
        headers = {"Authorization": auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert data["error"] == "invalid_signature"

    def test_hmac_sha1_signature(self):
        self.prepare_data()
        url = "/user"

        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "valid-token"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "hmac-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "GET", "http://localhost/user", params
        )
        sig = signature.hmac_sha1_signature(base_string, "secret", "valid-token-secret")
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param
        headers = {"Authorization": auth_header}

        # case 1: success
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert "username" in data

        # case 2: exists nonce
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert data["error"] == "invalid_nonce"

    def test_rsa_sha1_signature(self):
        self.prepare_data()
        url = "/user"

        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "valid-token"),
            ("oauth_signature_method", "RSA-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "rsa-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "GET", "http://localhost/user", params
        )
        sig = signature.rsa_sha1_signature(
            base_string, read_file_path("rsa_private.pem")
        )
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param
        headers = {"Authorization": auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert "username" in data

        # case: invalid signature
        auth_param = auth_param.replace("rsa-sha1-nonce", "alt-sha1-nonce")
        auth_header = "OAuth " + auth_param
        headers = {"Authorization": auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        assert data["error"] == "invalid_signature"


class ResourceDBTest(ResourceCacheTest):
    USE_CACHE = False
