import pytest
from flask import json

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"


class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class CodeChallenge(_CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["plain", "S256", "S128"]


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_missing_code_challenge(test_client):
    rv = test_client.get(authorize_url + "&code_challenge_method=plain")
    assert "Missing" in rv.location


def test_has_code_challenge(test_client):
    rv = test_client.get(
        authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    )
    assert rv.data == b"ok"


def test_invalid_code_challenge(test_client):
    rv = test_client.get(
        authorize_url + "&code_challenge=abc&code_challenge_method=plain"
    )
    assert "Invalid" in rv.location


def test_invalid_code_challenge_method(test_client):
    suffix = "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s&code_challenge_method=invalid"
    rv = test_client.get(authorize_url + suffix)
    assert "Unsupported" in rv.location


def test_supported_code_challenge_method(test_client):
    suffix = "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s&code_challenge_method=plain"
    rv = test_client.get(authorize_url + suffix)
    assert rv.data == b"ok"


def test_trusted_client_without_code_challenge(test_client, db, client):
    client.client_secret = "client-secret"
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(authorize_url)
    assert rv.data == b"ok"

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_code_verifier_without_code_challenge(test_client, db, client):
    """RFC 9700 Section 4.8.2: the authorization server MUST ensure that
    if there was no code_challenge in the authorization request, a
    request to the token endpoint containing a code_verifier is rejected."""
    client.client_secret = "client-secret"
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(authorize_url)
    assert rv.data == b"ok"

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": generate_token(48),
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_missing_code_verifier(test_client):
    url = authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "Missing" in resp["error_description"]


def test_trusted_client_missing_code_verifier(test_client, db, client):
    client.client_secret = "client-secret"
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    url = authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "Missing" in resp["error_description"]


def test_plain_code_challenge_invalid(test_client):
    url = authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "bar",
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "Invalid" in resp["error_description"]


def test_plain_code_challenge_failed(test_client):
    url = authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": generate_token(48),
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "failed" in resp["error_description"]


def test_plain_code_challenge_success(test_client):
    code_verifier = generate_token(48)
    url = authorize_url + "&code_challenge=" + code_verifier
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_s256_code_challenge_success(test_client):
    code_verifier = generate_token(48)
    code_challenge = create_s256_code_challenge(code_verifier)
    url = authorize_url + "&code_challenge=" + code_challenge
    url += "&code_challenge_method=S256"

    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_not_implemented_code_challenge_method(test_client):
    url = authorize_url + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
    url += "&code_challenge_method=S128"

    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    with pytest.raises(RuntimeError):
        test_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": generate_token(48),
                "client_id": "client-id",
            },
        )
