import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.multiple_response_types import NoneResponseTypeGrant
from authlib.oauth2.rfc9207 import IssuerParameter
from tests.util import parse_form

from .oauth2_server import register_form_post

authorize_url = "/oauth/authorize?response_type=none&client_id=client-id"


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(NoneResponseTypeGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "response_types": ["none"],
            "grant_types": [],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def query_params(rv):
    return dict(url_decode(urlparse.urlparse(rv.location).query))


def test_granted(test_client):
    """The response only contains state, in the query."""
    rv = test_client.post(authorize_url + "&state=bar", data={"user_id": "1"})
    assert rv.location.startswith("https://client.test/authorized?")
    assert query_params(rv) == {"state": "bar"}


def test_granted_without_state(test_client):
    """Without state, the client is redirected without parameters."""
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert rv.location == "https://client.test/authorized"


def test_denied(test_client):
    """A denied request returns access_denied with state."""
    rv = test_client.post(authorize_url + "&state=bar", data={})
    params = query_params(rv)
    assert params["error"] == "access_denied"
    assert params["state"] == "bar"


def test_unauthorized_client(test_client, client, db):
    """A client must be allowed to use the none response type."""
    client.set_client_metadata({**client.client_metadata, "response_types": ["code"]})
    db.session.commit()
    rv = test_client.get(authorize_url + "&state=bar&user_id=1")
    params = query_params(rv)
    assert params["error"] == "unauthorized_client"
    assert params["state"] == "bar"


def test_fragment_response_mode(test_client, server):
    """The client can ask for another response mode."""
    register_form_post(server)
    rv = test_client.post(
        authorize_url + "&state=bar&response_mode=fragment", data={"user_id": "1"}
    )
    fragment = urlparse.urlparse(rv.location).fragment
    assert dict(url_decode(fragment)) == {"state": "bar"}


def test_form_post_response_mode(test_client, server):
    """The response can be sent with an HTML form."""
    register_form_post(server)
    rv = test_client.post(
        authorize_url + "&state=bar&response_mode=form_post", data={"user_id": "1"}
    )
    form = parse_form(rv.data)
    assert form.action == "https://client.test/authorized"
    assert form.values == {"state": "bar"}


def test_query_response_mode(test_client, server):
    """The query response mode can be requested."""
    server.register_extension(MultipleResponseTypes())
    rv = test_client.post(
        authorize_url + "&state=bar&response_mode=query", data={"user_id": "1"}
    )
    assert query_params(rv) == {"state": "bar"}


class Issuer(IssuerParameter):
    def get_issuer(self):
        return "https://auth.test"


def test_issuer(test_client, server):
    """The response contains iss with RFC 9207."""
    server.register_extension(Issuer())
    rv = test_client.post(authorize_url + "&state=bar", data={"user_id": "1"})
    assert query_params(rv) == {"state": "bar", "iss": "https://auth.test"}


def test_combined_response_type(test_client):
    """The none response type cannot be combined with another one."""
    url = authorize_url.replace("none", "none%20code")
    rv = test_client.get(url + "&user_id=1")
    assert query_params(rv)["error"] == "unsupported_response_type"
