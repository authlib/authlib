import time

import pytest

from authlib.oauth1.rfc5849 import signature
from tests.util import decode_response
from tests.util import read_file_path

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
    yield db
    db.session.delete(client)


@pytest.mark.parametrize("use_cache", [True, False])
def test_temporary_credential_parameters_errors(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    rv = test_client.get(url)
    data = decode_response(rv.data)
    assert data["error"] == "method_not_allowed"

    # case 1
    rv = test_client.post(url)
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_consumer_key" in data["error_description"]

    # case 2
    rv = test_client.post(url, data={"oauth_consumer_key": "client"})
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_callback" in data["error_description"]

    # case 3
    rv = test_client.post(
        url, data={"oauth_consumer_key": "client", "oauth_callback": "invalid_url"}
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_request"
    assert "oauth_callback" in data["error_description"]

    # case 4
    rv = test_client.post(
        url, data={"oauth_consumer_key": "invalid-client", "oauth_callback": "oob"}
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_client"


@pytest.mark.parametrize("use_cache", [True, False])
def test_validate_timestamp_and_nonce(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    # case 5
    rv = test_client.post(
        url, data={"oauth_consumer_key": "client", "oauth_callback": "oob"}
    )
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_timestamp" in data["error_description"]

    # case 6
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_timestamp": str(int(time.time())),
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_nonce" in data["error_description"]

    # case 7
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_timestamp": "123",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_request"
    assert "oauth_timestamp" in data["error_description"]

    # case 8
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_timestamp": "sss",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_request"
    assert "oauth_timestamp" in data["error_description"]

    # case 9
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_timestamp": "-1",
            "oauth_signature_method": "PLAINTEXT",
        },
    )
    assert data["error"] == "invalid_request"
    assert "oauth_timestamp" in data["error_description"]


@pytest.mark.parametrize("use_cache", [True, False])
def test_temporary_credential_signatures_errors(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_signature" in data["error_description"]

    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "a",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_signature_method" in data["error_description"]

    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_signature_method": "INVALID",
            "oauth_callback": "oob",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "b",
            "oauth_signature": "c",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "unsupported_signature_method"


@pytest.mark.parametrize("use_cache", [True, False])
def test_plaintext_signature(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    # case 1: use payload
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case 2: use header
    auth_header = (
        'OAuth oauth_consumer_key="client",'
        'oauth_signature_method="PLAINTEXT",'
        'oauth_callback="oob",'
        'oauth_signature="secret&"'
    )
    headers = {"Authorization": auth_header}
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case 3: invalid signature
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "invalid-signature",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_signature"


@pytest.mark.parametrize("use_cache", [True, False])
def test_hmac_sha1_signature(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    params = [
        ("oauth_consumer_key", "client"),
        ("oauth_callback", "oob"),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", str(int(time.time()))),
        ("oauth_nonce", "hmac-sha1-nonce"),
    ]
    base_string = signature.construct_base_string(
        "POST", "http://localhost/oauth/initiate", params
    )
    sig = signature.hmac_sha1_signature(base_string, "secret", None)
    params.append(("oauth_signature", sig))
    auth_param = ",".join([f'{k}="{v}"' for k, v in params])
    auth_header = "OAuth " + auth_param
    headers = {"Authorization": auth_header}

    # case 1: success
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case 2: exists nonce
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert data["error"] == "invalid_nonce"


@pytest.mark.parametrize("use_cache", [True, False])
def test_rsa_sha1_signature(app, test_client, use_cache):
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"

    params = [
        ("oauth_consumer_key", "client"),
        ("oauth_callback", "oob"),
        ("oauth_signature_method", "RSA-SHA1"),
        ("oauth_timestamp", str(int(time.time()))),
        ("oauth_nonce", "rsa-sha1-nonce"),
    ]
    base_string = signature.construct_base_string(
        "POST", "http://localhost/oauth/initiate", params
    )
    sig = signature.rsa_sha1_signature(base_string, read_file_path("rsa_private.pem"))
    params.append(("oauth_signature", sig))
    auth_param = ",".join([f'{k}="{v}"' for k, v in params])
    auth_header = "OAuth " + auth_param
    headers = {"Authorization": auth_header}
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case: invalid signature
    auth_param = auth_param.replace("rsa-sha1-nonce", "alt-sha1-nonce")
    auth_header = "OAuth " + auth_param
    headers = {"Authorization": auth_header}
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert data["error"] == "invalid_signature"


@pytest.mark.parametrize("use_cache", [True, False])
def test_invalid_signature(app, test_client, use_cache):
    app.config.update({"OAUTH1_SUPPORTED_SIGNATURE_METHODS": ["INVALID"]})
    create_authorization_server(app, use_cache)
    url = "/oauth/initiate"
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "unsupported_signature_method"

    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "INVALID",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "invalid-nonce",
            "oauth_signature": "secret&",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "unsupported_signature_method"


@pytest.mark.parametrize("use_cache", [True, False])
def test_register_signature_method(app, test_client, use_cache):
    server = create_authorization_server(app, use_cache)

    def foo():
        pass

    server.register_signature_method("foo", foo)
    assert server.SIGNATURE_METHODS["foo"] == foo
