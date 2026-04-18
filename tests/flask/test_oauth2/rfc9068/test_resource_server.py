import time

import pytest
from flask import json
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from ..models import Token
from ..models import User
from ..models import db

issuer = "https://provider.test/"
resource_server = "resource-server-id"


@pytest.fixture(autouse=True)
def token_validator(jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return jwks

    validator = MyJWTBearerTokenValidator(
        issuer=issuer, resource_server=resource_server
    )
    return validator


@pytest.fixture(autouse=True)
def resource_protector(app, token_validator):
    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(token_validator)

    @app.route("/protected")
    @require_oauth()
    def protected():
        user = db.session.get(User, current_token["sub"])
        return jsonify(
            id=user.id,
            username=user.username,
            token=current_token._get_current_object(),
        )

    @app.route("/protected-by-scope")
    @require_oauth("profile")
    def protected_by_scope():
        user = db.session.get(User, current_token["sub"])
        return jsonify(
            id=user.id,
            username=user.username,
            token=current_token._get_current_object(),
        )

    @app.route("/protected-by-groups")
    @require_oauth(groups=["admins"])
    def protected_by_groups():
        user = db.session.get(User, current_token["sub"])
        return jsonify(
            id=user.id,
            username=user.username,
            token=current_token._get_current_object(),
        )

    @app.route("/protected-by-roles")
    @require_oauth(roles=["student"])
    def protected_by_roles():
        user = db.session.get(User, current_token["sub"])
        return jsonify(
            id=user.id,
            username=user.username,
            token=current_token._get_current_object(),
        )

    @app.route("/protected-by-entitlements")
    @require_oauth(entitlements=["captain"])
    def protected_by_entitlements():
        user = db.session.get(User, current_token["sub"])
        return jsonify(
            id=user.id,
            username=user.username,
            token=current_token._get_current_object(),
        )

    return require_oauth


@pytest.fixture
def jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def create_access_token_claims(client, user):
    now = int(time.time())
    expires_in = now + 3600
    auth_time = now - 60

    return {
        "iss": issuer,
        "exp": expires_in,
        "aud": resource_server,
        "sub": user.get_user_id(),
        "client_id": client.client_id,
        "iat": now,
        "jti": generate_token(16),
        "auth_time": auth_time,
        "scope": client.scope,
        "groups": ["admins"],
        "roles": ["student"],
        "entitlements": ["captain"],
    }


@pytest.fixture(autouse=True)
def claims(client, user):
    return create_access_token_claims(client, user)


def create_access_token(claims, jwks, alg="RS256", typ="at+jwt"):
    return jwt.encode(
        {"alg": alg, "typ": typ},
        claims,
        key=jwks,
    )


@pytest.fixture
def access_token(claims, jwks):
    return create_access_token(claims, jwks)


@pytest.fixture
def token(access_token, user):
    token = Token(
        user_id=user.user_id,
        client_id="resource-server",
        token_type="bearer",
        access_token=access_token,
        scope="profile",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    yield token
    db.session.delete(token)


def test_access_resource(test_client, access_token):
    headers = {"Authorization": f"Bearer {access_token}"}

    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"


def test_missing_authorization(test_client):
    rv = test_client.get("/protected")
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "missing_authorization"


def test_unsupported_token_type(test_client):
    headers = {"Authorization": "invalid token"}
    rv = test_client.get("/protected", headers=headers)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_token_type"


def test_invalid_token(test_client):
    headers = {"Authorization": "Bearer invalid"}
    rv = test_client.get("/protected", headers=headers)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_typ(test_client, access_token, claims, jwks):
    """The resource server MUST verify that the 'typ' header value is 'at+jwt' or
    'application/at+jwt' and reject tokens carrying any other value.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"

    access_token = create_access_token(claims, jwks, typ="application/at+jwt")

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"

    access_token = create_access_token(claims, jwks, typ="invalid")

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_missing_required_claims(test_client, client, user, jwks):
    required_claims = ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
    for claim in required_claims:
        claims = create_access_token_claims(client, user)
        del claims[claim]
        access_token = create_access_token(claims, jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = test_client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"


def test_invalid_iss(test_client, claims, jwks):
    """The issuer identifier for the authorization server (which is typically obtained
    during discovery) MUST exactly match the value of the 'iss' claim.
    """
    claims["iss"] = "invalid-issuer"
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_invalid_aud(test_client, claims, jwks):
    """The resource server MUST validate that the 'aud' claim contains a resource
    indicator value corresponding to an identifier the resource server expects for
    itself. The JWT access token MUST be rejected if 'aud' does not contain a
    resource indicator of the current resource server as a valid audience.
    """
    claims["aud"] = "invalid-resource-indicator"
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_invalid_exp(test_client, claims, jwks):
    """The current time MUST be before the time represented by the 'exp' claim.
    Implementers MAY provide for some small leeway, usually no more than a few
    minutes, to account for clock skew.
    """
    claims["exp"] = time.time() - 1
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_scope_restriction(test_client, claims, jwks):
    """If an authorization request includes a scope parameter, the corresponding
    issued JWT access token SHOULD include a 'scope' claim as defined in Section
    4.2 of [RFC8693]. All the individual scope strings in the 'scope' claim MUST
    have meaning for the resources indicated in the 'aud' claim. See Section 5 for
    more considerations about the relationship between scope strings and resources
    indicated by the 'aud' claim.
    """
    claims["scope"] = ["invalid-scope"]
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"

    rv = test_client.get("/protected-by-scope", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"


def test_entitlements_restriction(test_client, client, user, jwks):
    """Many authorization servers embed authorization attributes that go beyond the
    delegated scenarios described by [RFC7519] in the access tokens they issue.
    Typical examples include resource owner memberships in roles and groups that
    are relevant to the resource being accessed, entitlements assigned to the
    resource owner for the targeted resource that the authorization server knows
    about, and so on. An authorization server wanting to include such attributes
    in a JWT access token SHOULD use the 'groups', 'roles', and 'entitlements'
    attributes of the 'User' resource schema defined by Section 4.1.2 of
    [RFC7643]) as claim types.
    """
    for claim in ["groups", "roles", "entitlements"]:
        claims = create_access_token_claims(client, user)
        claims[claim] = ["invalid"]
        access_token = create_access_token(claims, jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = test_client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["username"] == "foo"

        rv = test_client.get(f"/protected-by-{claim}", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"


def test_extra_attributes(test_client, claims, jwks):
    """Authorization servers MAY return arbitrary attributes not defined in any
    existing specification, as long as the corresponding claim names are collision
    resistant or the access tokens are meant to be used only within a private
    subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.
    """
    claims["email"] = "user@example.org"
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["token"]["email"] == "user@example.org"


def test_invalid_auth_time(test_client, claims, jwks):
    claims["auth_time"] = "invalid-auth-time"
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_invalid_amr(test_client, claims, jwks):
    claims["amr"] = "invalid-amr"
    access_token = create_access_token(claims, jwks)

    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/protected", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"
