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
    yield client
    db.session.delete(client)


def prepare_temporary_credential(server):
    credential = {
        "oauth_token": "abc",
        "oauth_token_secret": "abc-secret",
        "oauth_verifier": "abc-verifier",
        "user": 1,
    }
    func = server._hooks["create_temporary_credential"]
    func(credential, "client", "oob")


def test_invalid_token_request_parameters(app, test_client):
    create_authorization_server(app, use_cache=True)
    url = "/oauth/token"

    # case 1
    rv = test_client.post(url)
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_consumer_key" in data["error_description"]

    # case 2
    rv = test_client.post(url, data={"oauth_consumer_key": "a"})
    data = decode_response(rv.data)
    assert data["error"] == "invalid_client"

    # case 3
    rv = test_client.post(url, data={"oauth_consumer_key": "client"})
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_token" in data["error_description"]

    # case 4
    rv = test_client.post(
        url, data={"oauth_consumer_key": "client", "oauth_token": "a"}
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_token"


def test_invalid_token_and_verifiers(app, test_client):
    server = create_authorization_server(app, use_cache=True)
    url = "/oauth/token"
    hook = server._hooks["create_temporary_credential"]

    # case 5
    hook({"oauth_token": "abc", "oauth_token_secret": "abc-secret"}, "client", "oob")
    rv = test_client.post(
        url, data={"oauth_consumer_key": "client", "oauth_token": "abc"}
    )
    data = decode_response(rv.data)
    assert data["error"] == "missing_required_parameter"
    assert "oauth_verifier" in data["error_description"]

    # case 6
    hook({"oauth_token": "abc", "oauth_token_secret": "abc-secret"}, "client", "oob")
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_token": "abc",
            "oauth_verifier": "abc",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_request"
    assert "oauth_verifier" in data["error_description"]


def test_duplicated_oauth_parameters(app, test_client):
    create_authorization_server(app, use_cache=True)
    url = "/oauth/token?oauth_consumer_key=client"
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_token": "abc",
            "oauth_verifier": "abc",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "duplicated_oauth_protocol_parameter"


def test_plaintext_signature(app, test_client):
    server = create_authorization_server(app, use_cache=True)
    url = "/oauth/token"

    # case 1: success
    prepare_temporary_credential(server)
    auth_header = (
        'OAuth oauth_consumer_key="client",'
        'oauth_signature_method="PLAINTEXT",'
        'oauth_token="abc",'
        'oauth_verifier="abc-verifier",'
        'oauth_signature="secret&abc-secret"'
    )
    headers = {"Authorization": auth_header}
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case 2: invalid signature
    prepare_temporary_credential(server)
    rv = test_client.post(
        url,
        data={
            "oauth_consumer_key": "client",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_token": "abc",
            "oauth_verifier": "abc-verifier",
            "oauth_signature": "invalid-signature",
        },
    )
    data = decode_response(rv.data)
    assert data["error"] == "invalid_signature"


def test_hmac_sha1_signature(app, test_client):
    server = create_authorization_server(app, use_cache=True)
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
        "POST", "http://localhost/oauth/token", params
    )
    sig = signature.hmac_sha1_signature(base_string, "secret", "abc-secret")
    params.append(("oauth_signature", sig))
    auth_param = ",".join([f'{k}="{v}"' for k, v in params])
    auth_header = "OAuth " + auth_param
    headers = {"Authorization": auth_header}

    # case 1: success
    prepare_temporary_credential(server)
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert "oauth_token" in data

    # case 2: exists nonce
    prepare_temporary_credential(server)
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert data["error"] == "invalid_nonce"


def test_rsa_sha1_signature(app, test_client):
    server = create_authorization_server(app, use_cache=True)
    url = "/oauth/token"

    prepare_temporary_credential(server)
    params = [
        ("oauth_consumer_key", "client"),
        ("oauth_token", "abc"),
        ("oauth_verifier", "abc-verifier"),
        ("oauth_signature_method", "RSA-SHA1"),
        ("oauth_timestamp", str(int(time.time()))),
        ("oauth_nonce", "rsa-sha1-nonce"),
    ]
    base_string = signature.construct_base_string(
        "POST", "http://localhost/oauth/token", params
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
    prepare_temporary_credential(server)
    auth_param = auth_param.replace("rsa-sha1-nonce", "alt-sha1-nonce")
    auth_header = "OAuth " + auth_param
    headers = {"Authorization": auth_header}
    rv = test_client.post(url, headers=headers)
    data = decode_response(rv.data)
    assert data["error"] == "invalid_signature"
