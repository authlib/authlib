import json
import time

from django.http import JsonResponse
from django.test import override_settings

from authlib.common.encoding import to_unicode
from authlib.common.urls import add_params_to_uri
from authlib.integrations.django_oauth1 import ResourceProtector
from authlib.oauth1.rfc5849 import signature
from tests.util import read_file_path

from .models import Client
from .models import TokenCredential
from .models import User
from .oauth1_server import TestCase


class ResourceTest(TestCase):
    def create_route(self):
        require_oauth = ResourceProtector(Client, TokenCredential)

        @require_oauth()
        def handle(request):
            user = request.oauth1_credential.user
            return JsonResponse(dict(username=user.username))

        return handle

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

        tok = TokenCredential(
            user_id=user.pk,
            client_id=client.client_id,
            oauth_token="valid-token",
            oauth_token_secret="valid-token-secret",
        )
        tok.save()

    def test_invalid_request_parameters(self):
        self.prepare_data()
        handle = self.create_route()
        url = "/user"

        # case 1
        request = self.factory.get(url)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "missing_required_parameter"
        assert "oauth_consumer_key" in data["error_description"]

        # case 2
        request = self.factory.get(add_params_to_uri(url, {"oauth_consumer_key": "a"}))
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "invalid_client"

        # case 3
        request = self.factory.get(
            add_params_to_uri(url, {"oauth_consumer_key": "client"})
        )
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "missing_required_parameter"
        assert "oauth_token" in data["error_description"]

        # case 4
        request = self.factory.get(
            add_params_to_uri(url, {"oauth_consumer_key": "client", "oauth_token": "a"})
        )
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "invalid_token"

        # case 5
        request = self.factory.get(
            add_params_to_uri(
                url, {"oauth_consumer_key": "client", "oauth_token": "valid-token"}
            )
        )
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "missing_required_parameter"
        assert "oauth_timestamp" in data["error_description"]

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["PLAINTEXT"]})
    def test_plaintext_signature(self):
        self.prepare_data()
        handle = self.create_route()
        url = "/user"

        # case 1: success
        auth_header = (
            'OAuth oauth_consumer_key="client",'
            'oauth_signature_method="PLAINTEXT",'
            'oauth_token="valid-token",'
            'oauth_signature="secret&valid-token-secret"'
        )
        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert "username" in data

        # case 2: invalid signature
        auth_header = auth_header.replace("valid-token-secret", "invalid")
        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "invalid_signature"

    def test_hmac_sha1_signature(self):
        self.prepare_data()
        handle = self.create_route()
        url = "/user"

        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "valid-token"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "hmac-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "GET", "http://testserver/user", params
        )
        sig = signature.hmac_sha1_signature(base_string, "secret", "valid-token-secret")
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param

        # case 1: success
        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert "username" in data

        # case 2: exists nonce
        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "invalid_nonce"

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["RSA-SHA1"]})
    def test_rsa_sha1_signature(self):
        self.prepare_data()
        handle = self.create_route()

        url = "/user"

        params = [
            ("oauth_consumer_key", "client"),
            ("oauth_token", "valid-token"),
            ("oauth_signature_method", "RSA-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_nonce", "rsa-sha1-nonce"),
        ]
        base_string = signature.construct_base_string(
            "GET", "http://testserver/user", params
        )
        sig = signature.rsa_sha1_signature(
            base_string, read_file_path("rsa_private.pem")
        )
        params.append(("oauth_signature", sig))
        auth_param = ",".join([f'{k}="{v}"' for k, v in params])
        auth_header = "OAuth " + auth_param

        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert "username" in data

        # case: invalid signature
        auth_param = auth_param.replace("rsa-sha1-nonce", "alt-sha1-nonce")
        auth_header = "OAuth " + auth_param
        request = self.factory.get(url, HTTP_AUTHORIZATION=auth_header)
        resp = handle(request)
        data = json.loads(to_unicode(resp.content))
        assert data["error"] == "invalid_signature"
