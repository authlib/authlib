import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import grants

from .models import Client
from .models import User
from .oauth2_server import TestCase


class ImplicitTest(TestCase):
    def create_server(self):
        server = super().create_server()
        server.register_grant(grants.ImplicitGrant)
        return server

    def prepare_data(self, response_type="token", scope=""):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            response_type=response_type,
            scope=scope,
            token_endpoint_auth_method="none",
            default_redirect_uri="https://a.b",
        )
        client.save()

    def test_get_consent_grant_client(self):
        server = self.create_server()
        url = "/authorize?response_type=token"
        request = self.factory.get(url)
        with pytest.raises(errors.InvalidClientError):
            server.get_consent_grant(request)

        url = "/authorize?response_type=token&client_id=client"
        request = self.factory.get(url)
        with pytest.raises(errors.InvalidClientError):
            server.get_consent_grant(request)

        self.prepare_data(response_type="")
        with pytest.raises(errors.UnauthorizedClientError):
            server.get_consent_grant(request)

    def test_get_consent_grant_scope(self):
        server = self.create_server()
        server.scopes_supported = ["profile"]

        self.prepare_data()
        base_url = "/authorize?response_type=token&client_id=client"
        url = base_url + "&scope=invalid"
        request = self.factory.get(url)
        with pytest.raises(errors.InvalidScopeError):
            server.get_consent_grant(request)

    def test_create_authorization_response(self):
        server = self.create_server()
        self.prepare_data()
        data = {"response_type": "token", "client_id": "client"}
        request = self.factory.post("/authorize", data=data)
        grant = server.get_consent_grant(request)

        resp = server.create_authorization_response(request, grant=grant)
        assert resp.status_code == 302
        params = dict(url_decode(urlparse.urlparse(resp["Location"]).fragment))
        assert params["error"] == "access_denied"

        grant_user = User.objects.get(username="foo")
        resp = server.create_authorization_response(
            request, grant=grant, grant_user=grant_user
        )
        assert resp.status_code == 302
        params = dict(url_decode(urlparse.urlparse(resp["Location"]).fragment))
        assert "access_token" in params
