import time

from django.core.cache import cache
from django.test import override_settings

from authlib.oauth1.rfc5849 import signature
from tests.util import decode_response
from tests.util import read_file_path

from .models import Client
from .models import User
from .oauth1_server import TestCase


class AuthorizationTest(TestCase):
    def prepare_data(self):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            client_secret="secret",
            default_redirect_uri="https://a.b",
        )
        client.save()

    def prepare_temporary_credential(self, server):
        token = {
            "oauth_token": "abc",
            "oauth_token_secret": "abc-secret",
            "oauth_verifier": "abc-verifier",
            "client_id": "client",
            "user_id": 1,
        }
        key_prefix = server._temporary_credential_key_prefix
        key = key_prefix + token["oauth_token"]
        cache.set(key, token, timeout=server._temporary_expires_in)

    def test_invalid_token_request_parameters(self):
        self.prepare_data()
        server = self.create_server()
        url = "/oauth/token"

        # case 1
        request = self.factory.post(url)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_consumer_key" in data["error_description"]

        # case 2
        request = self.factory.post(url, data={"oauth_consumer_key": "a"})
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "invalid_client"

        # case 3
        request = self.factory.post(url, data={"oauth_consumer_key": "client"})
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_token" in data["error_description"]

        # case 4
        request = self.factory.post(
            url, data={"oauth_consumer_key": "client", "oauth_token": "a"}
        )
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "invalid_token"

    def test_duplicated_oauth_parameters(self):
        self.prepare_data()
        server = self.create_server()
        url = "/oauth/token?oauth_consumer_key=client"
        request = self.factory.post(
            url,
            data={
                "oauth_consumer_key": "client",
                "oauth_token": "abc",
                "oauth_verifier": "abc",
            },
        )
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "duplicated_oauth_protocol_parameter"

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["PLAINTEXT"]})
    def test_plaintext_signature(self):
        self.prepare_data()
        server = self.create_server()
        url = "/oauth/token"

        # case 1: success
        self.prepare_temporary_credential(server)
        auth_header = (
            'OAuth oauth_consumer_key="client",'
            'oauth_signature_method="PLAINTEXT",'
            'oauth_token="abc",'
            'oauth_verifier="abc-verifier",'
            'oauth_signature="secret&abc-secret"'
        )
        request = self.factory.post(url, HTTP_AUTHORIZATION=auth_header)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert "oauth_token" in data

        # case 2: invalid signature
        self.prepare_temporary_credential(server)
        request = self.factory.post(
            url,
            data={
                "oauth_consumer_key": "client",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_token": "abc",
                "oauth_verifier": "abc-verifier",
                "oauth_signature": "invalid-signature",
            },
        )
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "invalid_signature"

    def test_hmac_sha1_signature(self):
        self.prepare_data()
        server = self.create_server()
        url = "/oauth/token"

        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "abc"),
            ("oauth_verifier", "abc-verifier"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "hmac-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "POST", "http://testserver/oauth/token", params
        )
        sig = signature.hmac_sha1_signature(base_string, "secret", "abc-secret")
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param

        # case 1: success
        self.prepare_temporary_credential(server)
        request = self.factory.post(url, HTTP_AUTHORIZATION=auth_header)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert "oauth_token" in data

        # case 2: exists nonce
        self.prepare_temporary_credential(server)
        request = self.factory.post(url, HTTP_AUTHORIZATION=auth_header)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "invalid_nonce"

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["RSA-SHA1"]})
    def test_rsa_sha1_signature(self):
        self.prepare_data()
        server = self.create_server()
        url = "/oauth/token"

        self.prepare_temporary_credential(server)
        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "abc"),
            ("oauth_verifier", "abc-verifier"),
            ("oauth_signature_method", "RSA-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "rsa-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "POST", "http://testserver/oauth/token", params
        )
        sig = signature.rsa_sha1_signature(
            base_string, read_file_path("rsa_private.pem")
        )
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param

        request = self.factory.post(url, HTTP_AUTHORIZATION=auth_header)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert "oauth_token" in data

        # case: invalid signature
        self.prepare_temporary_credential(server)
        auth_param = auth_param.replace("rsa-sha1-nonce", "alt-sha1-nonce")
        auth_header = "OAuth " + auth_param
        request = self.factory.post(url, HTTP_AUTHORIZATION=auth_header)
        resp = server.create_token_response(request)
        data = decode_response(resp.content)
        assert data["error"] == "invalid_signature"
