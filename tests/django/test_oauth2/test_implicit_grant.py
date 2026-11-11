import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import grants

from .models import Client
from .models import User


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(grants.ImplicitGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        response_type="token",
        scope="",
        token_endpoint_auth_method="none",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_get_consent_grant_client(factory, server, client, user):
    url = "/authorize?response_type=token"
    request = factory.get(url)
    with pytest.raises(errors.InvalidClientError):
        server.get_consent_grant(request, end_user=user)

    url = "/authorize?response_type=token&client_id=invalid-id"
    request = factory.get(url)
    with pytest.raises(errors.InvalidClientError):
        server.get_consent_grant(request, end_user=user)

    client.response_type = ""
    client.save()
    url = "/authorize?response_type=token&client_id=client-id"
    request = factory.get(url)
    with pytest.raises(errors.UnauthorizedClientError):
        server.get_consent_grant(request, end_user=user)


def test_get_consent_grant_scope(factory, server, user):
    server.scopes_supported = ["profile"]

    base_url = "/authorize?response_type=token&client_id=client-id"
    url = base_url + "&scope=invalid"
    request = factory.get(url)
    with pytest.raises(errors.InvalidScopeError):
        server.get_consent_grant(request, end_user=user)


def test_create_authorization_response(factory, server):
    data = {"response_type": "token", "client_id": "client-id"}
    request = factory.post("/authorize", data=data)
    grant = server.get_consent_grant(request)

    resp = server.create_authorization_response(request, grant=grant)
    assert resp.status_code == 303
    params = dict(url_decode(urlparse.urlparse(resp["Location"]).fragment))
    assert params["error"] == "access_denied"

    grant_user = User.objects.get(username="foo")
    resp = server.create_authorization_response(
        request, grant=grant, grant_user=grant_user
    )
    assert resp.status_code == 303
    params = dict(url_decode(urlparse.urlparse(resp["Location"]).fragment))
    assert "access_token" in params


def test_framework_request(factory, server):
    """The OAuth 2.0 request gives access to the Django request."""
    request = factory.get("/authorize?response_type=token")
    assert server.create_oauth2_request(request).framework_request is request
