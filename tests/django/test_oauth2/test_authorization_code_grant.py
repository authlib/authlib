import json
import os

import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import grants

from .models import Client
from .models import CodeGrantMixin
from .models import OAuth2Code
from .models import User
from .oauth2_server import create_basic_auth


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            auth_code = OAuth2Code(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.payload.redirect_uri,
                response_type=request.payload.response_type,
                scope=request.payload.scope,
                user=request.user,
            )
            auth_code.save()

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        response_type="code",
        grant_type="authorization_code",
        scope="",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_get_consent_grant_client(factory, server, client):
    url = "/authorize?response_type=code"
    request = factory.get(url)
    with pytest.raises(errors.InvalidClientError):
        server.get_consent_grant(request)

    url = "/authorize?response_type=code&client_id=invalid-id"
    request = factory.get(url)
    with pytest.raises(errors.InvalidClientError):
        server.get_consent_grant(request)

    client.response_type = ""
    client.save()
    url = "/authorize?response_type=code&client_id=client-id"
    request = factory.get(url)
    with pytest.raises(errors.UnauthorizedClientError):
        server.get_consent_grant(request)

    url = "/authorize?response_type=code&client_id=client-id&scope=profile&state=bar&redirect_uri=https%3A%2F%2Fclient.test&response_type=code"
    request = factory.get(url)
    with pytest.raises(errors.InvalidRequestError):
        server.get_consent_grant(request)


def test_get_consent_grant_redirect_uri(factory, server):
    base_url = "/authorize?response_type=code&client_id=client-id"
    url = base_url + "&redirect_uri=https%3A%2F%2Fa.c"
    request = factory.get(url)
    with pytest.raises(errors.InvalidRequestError):
        server.get_consent_grant(request)

    url = base_url + "&redirect_uri=https%3A%2F%2Fclient.test"
    request = factory.get(url)
    grant = server.get_consent_grant(request)
    assert isinstance(grant, grants.AuthorizationCodeGrant)


def test_get_consent_grant_scope(factory, server):
    server.scopes_supported = ["profile"]
    base_url = "/authorize?response_type=code&client_id=client-id"
    url = base_url + "&scope=invalid"
    request = factory.get(url)
    with pytest.raises(errors.InvalidScopeError):
        server.get_consent_grant(request)


def test_create_authorization_response(factory, server):
    data = {"response_type": "code", "client_id": "client-id"}
    request = factory.post("/authorize", data=data)
    grant = server.get_consent_grant(request)

    resp = server.create_authorization_response(request, grant=grant)
    assert resp.status_code == 302
    assert "error=access_denied" in resp["Location"]

    grant_user = User.objects.get(username="foo")
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert resp.status_code == 302
    assert "code=" in resp["Location"]


def test_create_token_response_invalid(factory, server):
    # case: no auth
    request = factory.post("/oauth/token", data={"grant_type": "authorization_code"})
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    auth_header = create_basic_auth("client-id", "client-secret")

    # case: no code
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"

    # case: invalid code
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": "invalid"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_grant"


def test_create_token_response_success(factory, server):
    data = get_token_response(factory, server)
    assert "access_token" in data
    assert "refresh_token" not in data


def test_create_token_response_with_refresh_token(factory, server, client, settings):
    settings.AUTHLIB_OAUTH2_PROVIDER["refresh_token_generator"] = True
    server.load_config(settings.AUTHLIB_OAUTH2_PROVIDER)
    client.grant_type = "authorization_code\nrefresh_token"
    client.save()
    data = get_token_response(factory, server)
    assert "access_token" in data
    assert "refresh_token" in data


def test_insecure_transport_error_with_payload_access(factory, server):
    """Test that InsecureTransportError is raised properly without AttributeError
    when accessing request.payload on non-HTTPS requests (issue #795)."""
    del os.environ["AUTHLIB_INSECURE_TRANSPORT"]

    request = factory.get(
        "https://provider.test/authorize?response_type=code&client_id=client-id"
    )

    with pytest.raises(errors.InsecureTransportError):
        server.get_consent_grant(request)


def get_token_response(factory, server):
    data = {"response_type": "code", "client_id": "client-id"}
    request = factory.post("/authorize", data=data)
    grant_user = User.objects.get(username="foo")
    grant = server.get_consent_grant(request)
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert resp.status_code == 302

    params = dict(url_decode(urlparse.urlparse(resp["Location"]).query))
    code = params["code"]

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": code},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    return data
