import pytest
from flask import json

import authlib.oidc.core as oidc_core
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.jose import JsonWebToken
from authlib.jose import jwt
from tests.util import read_file_path

from .models import Token


@pytest.fixture(autouse=True)
def server(server, app, db):
    class UserInfoEndpoint(oidc_core.UserInfoEndpoint):
        def get_issuer(self) -> str:
            return "https://provider.test"

        def generate_user_info(self, user, scope):
            return user.generate_user_info().filter(scope)

        def resolve_private_key(self):
            return read_file_path("jwks_private.json")

    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    resource_protector = ResourceProtector()
    resource_protector.register_token_validator(BearerTokenValidator())
    server.register_endpoint(UserInfoEndpoint(resource_protector=resource_protector))

    @app.route("/oauth/userinfo", methods=["GET", "POST"])
    def userinfo():
        return server.create_endpoint_response("userinfo")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def token(db):
    token = Token(
        user_id=1,
        client_id="client-id",
        token_type="bearer",
        access_token="access-token",
        refresh_token="r1",
        scope="openid",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    yield token
    db.session.delete(token)


def test_get(test_client, db, token):
    """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
    The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

    token.scope = "openid profile email address phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/json"

    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
        "birthdate": "2000-12-01",
        "email": "janedoe@example.com",
        "email_verified": True,
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_post(test_client, db, token):
    """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
    The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

    token.scope = "openid profile email address phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/json"

    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
        "birthdate": "2000-12-01",
        "email": "janedoe@example.com",
        "email_verified": True,
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_no_token(test_client):
    rv = test_client.post("/oauth/userinfo")
    resp = json.loads(rv.data)
    assert resp["error"] == "missing_authorization"


def test_bad_token(test_client):
    headers = {"Authorization": "invalid token_string"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_token_type"


def test_token_has_bad_scope(test_client, db, token):
    """Test that tokens without 'openid' scope cannot access the userinfo endpoint."""

    token.scope = "foobar"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.post("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"


def test_scope_minimum(test_client):
    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
    }


def test_scope_profile(test_client, db, token):
    token.scope = "openid profile"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "birthdate": "2000-12-01",
        "family_name": "Doe",
        "gender": "female",
        "given_name": "Jane",
        "locale": "fr-FR",
        "middle_name": "Middle",
        "name": "foo",
        "nickname": "Jany",
        "picture": "https://resource.test/janedoe/me.jpg",
        "preferred_username": "j.doe",
        "profile": "https://resource.test/janedoe",
        "updated_at": 1745315119,
        "website": "https://resource.test",
        "zoneinfo": "Europe/Paris",
    }


def test_scope_address(test_client, db, token):
    token.scope = "openid address"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "address": {
            "country": "USA",
            "formatted": "742 Evergreen Terrace, Springfield",
            "locality": "Springfield",
            "postal_code": "1245",
            "region": "Unknown",
            "street_address": "742 Evergreen Terrace",
        },
    }


def test_scope_email(test_client, db, token):
    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "email": "janedoe@example.com",
        "email_verified": True,
    }


def test_scope_phone(test_client, db, token):
    token.scope = "openid phone"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    resp = json.loads(rv.data)
    assert resp == {
        "sub": "1",
        "phone_number": "+1 (425) 555-1212",
        "phone_number_verified": False,
    }


def test_scope_signed_unsecured(test_client, db, token, client):
    """When userinfo_signed_response_alg is set as client metadata, the userinfo response must be a JWT."""
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "userinfo_signed_response_alg": "none",
        }
    )
    db.session.add(client)
    db.session.commit()

    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/jwt"

    jwt_none = JsonWebToken(["none"])
    claims = jwt_none.decode(rv.data, None)
    assert claims == {
        "sub": "1",
        "iss": "https://provider.test",
        "aud": "client-id",
        "email": "janedoe@example.com",
        "email_verified": True,
    }


def test_scope_signed_secured(test_client, client, token, db):
    """When userinfo_signed_response_alg is set as client metadata and not none, the userinfo response must be signed."""
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "userinfo_signed_response_alg": "RS256",
        }
    )
    db.session.add(client)
    db.session.commit()

    token.scope = "openid email"
    db.session.add(token)
    db.session.commit()

    headers = {"Authorization": "Bearer access-token"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/jwt"

    pub_key = read_file_path("jwks_public.json")
    claims = jwt.decode(rv.data, pub_key)
    assert claims == {
        "sub": "1",
        "iss": "https://provider.test",
        "aud": "client-id",
        "email": "janedoe@example.com",
        "email_verified": True,
    }
