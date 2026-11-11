import json

import pytest

from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from authlib.oauth2.rfc7592 import ClientConfigurationEndpoint
from tests.util import INVALID_JSON_BODIES

from .models import Client
from .models import OAuth2Token


class MyClientRegistrationEndpoint(ClientRegistrationEndpoint):
    def authenticate_token(self, request):
        return request.headers.get("Authorization")

    def get_server_metadata(self):
        return {}


class MyClientConfigurationEndpoint(ClientConfigurationEndpoint):
    def authenticate_token(self, request):
        return OAuth2Token.objects.get(access_token="a1")

    def authenticate_client(self, request):
        return Client.objects.get(client_id="client-id")

    def check_permission(self, client, request):
        return True

    def get_server_metadata(self):
        return {}


@pytest.fixture(autouse=True)
def server(server):
    server.register_endpoint(MyClientRegistrationEndpoint)
    server.register_endpoint(MyClientConfigurationEndpoint)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(user_id=user.pk, client_id="client-id")
    client.save()
    yield client
    client.delete()


@pytest.mark.parametrize("body", INVALID_JSON_BODIES)
def test_register_body_not_json_object(factory, server, body):
    """A body that is not a JSON object gets an invalid_request error."""
    request = factory.post(
        "/register",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION="bearer abc",
    )
    resp = server.create_endpoint_response("client_registration", request)
    assert resp.status_code == 400
    assert json.loads(resp.content)["error"] == "invalid_request"


@pytest.mark.parametrize("body", INVALID_JSON_BODIES)
def test_update_body_not_json_object(factory, server, token, body):
    """A body that is not a JSON object gets an invalid_request error."""
    request = factory.put(
        "/register/client-id",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION="bearer a1",
    )
    resp = server.create_endpoint_response("client_configuration", request)
    assert resp.status_code == 400
    assert json.loads(resp.content)["error"] == "invalid_request"
