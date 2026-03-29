import pytest

from tests.util import decode_response

from .oauth1_server import Client
from .oauth1_server import User
from .oauth1_server import create_authorization_server


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture(autouse=True)
def client(db, user):
    client = Client(
        user_id=user.id,
        client_id="client",
        client_secret="secret",
        default_redirect_uri="https://client.test",
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


@pytest.mark.parametrize("use_cache", [True, False])
def test_invalid_authorization(app, test_client, use_cache):
    create_authorization_server(app, use_cache, use_cache)
    url = "/oauth/authorize"

    # case 1
    rv = test_client.post(url, data={"user_id": "1"})
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_token" in data["error_description"]

    # case 2
    rv = test_client.post(url, data={"user_id": "1", "oauth_token": "a"})
    data = decode_response(rv.data)
    assert data["error"] == "invalid_token"


@pytest.mark.parametrize("use_cache", [True, False])
def test_authorize_denied(app, test_client, use_cache):
    create_authorization_server(app, use_cache, use_cache)
    initiate_url = "/oauth/initiate"
    authorize_url = "/oauth/authorize"

    rv = test_client.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert "oauth_token" in data

    rv = test_client.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    assert rv.status_code == 302
    assert "access_denied" in rv.headers["Location"]
    assert "https://client.test" in rv.headers["Location"]

    rv = test_client.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "https://i.test",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert "oauth_token" in data

    rv = test_client.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    assert rv.status_code == 302
    assert "access_denied" in rv.headers["Location"]
    assert "https://i.test" in rv.headers["Location"]


@pytest.mark.parametrize("use_cache", [True, False])
def test_authorize_granted(app, test_client, use_cache):
    create_authorization_server(app, use_cache, use_cache)
    initiate_url = "/oauth/initiate"
    authorize_url = "/oauth/authorize"

    rv = test_client.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert "oauth_token" in data

    rv = test_client.post(
        authorize_url, data={"user_id": "1", "oauth_token": data["oauth_token"]}
    )
    assert rv.status_code == 302
    assert "oauth_verifier" in rv.headers["Location"]
    assert "https://client.test" in rv.headers["Location"]

    rv = test_client.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "https://i.test",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert "oauth_token" in data

    rv = test_client.post(
        authorize_url, data={"user_id": "1", "oauth_token": data["oauth_token"]}
    )
    assert rv.status_code == 302
    assert "oauth_verifier" in rv.headers["Location"]
    assert "https://i.test" in rv.headers["Location"]
