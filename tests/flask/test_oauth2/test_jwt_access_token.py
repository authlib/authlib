import time

import pytest
from flask import json
from flask import jsonify

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from authlib.oauth2.rfc9068 import JWTIntrospectionEndpoint
from authlib.oauth2.rfc9068 import JWTRevocationEndpoint
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


def create_token_validator(issuer, resource_server, jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return jwks

    validator = MyJWTBearerTokenValidator(
        issuer=issuer, resource_server=resource_server
    )
    return validator


def create_resource_protector(app, validator):
    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(validator)

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


def create_token_generator(authorization_server, issuer, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    authorization_server.register_token_generator("default", token_generator)
    return token_generator


def create_introspection_endpoint(app, authorization_server, issuer, jwks):
    class MyJWTIntrospectionEndpoint(JWTIntrospectionEndpoint):
        def get_jwks(self):
            return jwks

        def check_permission(self, token, client, request):
            return client.client_id == "client-id"

    endpoint = MyJWTIntrospectionEndpoint(issuer=issuer)
    authorization_server.register_endpoint(endpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return authorization_server.create_endpoint_response(
            MyJWTIntrospectionEndpoint.ENDPOINT_NAME
        )

    return endpoint


def create_revocation_endpoint(app, authorization_server, issuer, jwks):
    class MyJWTRevocationEndpoint(JWTRevocationEndpoint):
        def get_jwks(self):
            return jwks

    endpoint = MyJWTRevocationEndpoint(issuer=issuer)
    authorization_server.register_endpoint(endpoint)

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return authorization_server.create_endpoint_response(
            MyJWTRevocationEndpoint.ENDPOINT_NAME
        )

    return endpoint


def create_user():
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    return user


def create_oauth_client(client_id, user):
    oauth_client = Client(
        user_id=user.id,
        client_id=client_id,
        client_secret=client_id,
    )
    oauth_client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["http://localhost/authorized"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(oauth_client)
    db.session.commit()
    return oauth_client


def create_access_token_claims(client, user, issuer, **kwargs):
    now = int(time.time())
    expires_in = now + 3600
    auth_time = now - 60

    return {
        "iss": kwargs.get("issuer", issuer),
        "exp": kwargs.get("exp", expires_in),
        "aud": kwargs.get("aud", client.client_id),
        "sub": kwargs.get("sub", user.get_user_id()),
        "client_id": kwargs.get("client_id", client.client_id),
        "iat": kwargs.get("iat", now),
        "jti": kwargs.get("jti", generate_token(16)),
        "auth_time": kwargs.get("auth_time", auth_time),
        "scope": kwargs.get("scope", client.scope),
        "groups": kwargs.get("groups", ["admins"]),
        "roles": kwargs.get("groups", ["student"]),
        "entitlements": kwargs.get("groups", ["captain"]),
    }


def create_access_token(claims, jwks, alg="RS256", typ="at+jwt"):
    header = {"alg": alg, "typ": typ}
    access_token = jwt.encode(
        header,
        claims,
        key=jwks,
        check=False,
    )
    return access_token.decode()


def create_token(access_token):
    token = Token(
        user_id=1,
        client_id="resource-server",
        token_type="bearer",
        access_token=access_token,
        scope="profile",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    return token


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class JWTAccessTokenGenerationTest(TestCase):
    def setUp(self):
        super().setUp()
        self.issuer = "https://authlib.org/"
        self.jwks = read_file_path("jwks_private.json")
        self.authorization_server = create_authorization_server(self.app)
        self.authorization_server.register_grant(AuthorizationCodeGrant)
        self.token_generator = create_token_generator(
            self.authorization_server, self.issuer, self.jwks
        )
        self.user = create_user()
        self.oauth_client = create_oauth_client("client-id", self.user)

    def test_generate_jwt_access_token(self):
        res = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": self.oauth_client.response_types[0],
                "client_id": self.oauth_client.client_id,
                "redirect_uri": self.oauth_client.redirect_uris[0],
                "scope": self.oauth_client.scope,
                "user_id": self.user.id,
            },
        )

        params = dict(url_decode(urlparse.urlparse(res.location).query))
        code = params["code"]
        res = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.oauth_client.client_id,
                "client_secret": self.oauth_client.client_secret,
                "scope": " ".join(self.oauth_client.scope),
                "redirect_uri": self.oauth_client.redirect_uris[0],
            },
        )

        access_token = res.json["access_token"]
        claims = jwt.decode(access_token, self.jwks)

        assert claims["iss"] == self.issuer
        assert claims["sub"] == self.user.id
        assert claims["scope"] == self.oauth_client.scope
        assert claims["client_id"] == self.oauth_client.client_id

        # This specification registers the 'application/at+jwt' media type, which can
        # be used to indicate that the content is a JWT access token. JWT access tokens
        # MUST include this media type in the 'typ' header parameter to explicitly
        # declare that the JWT represents an access token complying with this profile.
        # Per the definition of 'typ' in Section 4.1.9 of [RFC7515], it is RECOMMENDED
        # that the 'application/' prefix be omitted. Therefore, the 'typ' value used
        # SHOULD be 'at+jwt'.

        assert claims.header["typ"] == "at+jwt"

    def test_generate_jwt_access_token_extra_claims(self):
        """Authorization servers MAY return arbitrary attributes not defined in any
        existing specification, as long as the corresponding claim names are collision
        resistant or the access tokens are meant to be used only within a private
        subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.
        """

        def get_extra_claims(client, grant_type, user, scope):
            return {"username": user.username}

        self.token_generator.get_extra_claims = get_extra_claims

        res = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": self.oauth_client.response_types[0],
                "client_id": self.oauth_client.client_id,
                "redirect_uri": self.oauth_client.redirect_uris[0],
                "scope": self.oauth_client.scope,
                "user_id": self.user.id,
            },
        )

        params = dict(url_decode(urlparse.urlparse(res.location).query))
        code = params["code"]
        res = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.oauth_client.client_id,
                "client_secret": self.oauth_client.client_secret,
                "scope": " ".join(self.oauth_client.scope),
                "redirect_uri": self.oauth_client.redirect_uris[0],
            },
        )

        access_token = res.json["access_token"]
        claims = jwt.decode(access_token, self.jwks)
        assert claims["username"] == self.user.username

    @pytest.mark.skip
    def test_generate_jwt_access_token_no_user(self):
        res = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": self.oauth_client.response_types[0],
                "client_id": self.oauth_client.client_id,
                "redirect_uri": self.oauth_client.redirect_uris[0],
                "scope": self.oauth_client.scope,
                #'user_id': self.user.id,
            },
        )

        params = dict(url_decode(urlparse.urlparse(res.location).query))
        code = params["code"]
        res = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.oauth_client.client_id,
                "client_secret": self.oauth_client.client_secret,
                "scope": " ".join(self.oauth_client.scope),
                "redirect_uri": self.oauth_client.redirect_uris[0],
            },
        )

        access_token = res.json["access_token"]
        claims = jwt.decode(access_token, self.jwks)

        assert claims["sub"] == self.oauth_client.client_id

    def test_optional_fields(self):
        self.token_generator.get_auth_time = lambda *args: 1234
        self.token_generator.get_amr = lambda *args: "amr"
        self.token_generator.get_acr = lambda *args: "acr"

        res = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": self.oauth_client.response_types[0],
                "client_id": self.oauth_client.client_id,
                "redirect_uri": self.oauth_client.redirect_uris[0],
                "scope": self.oauth_client.scope,
                "user_id": self.user.id,
            },
        )

        params = dict(url_decode(urlparse.urlparse(res.location).query))
        code = params["code"]
        res = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.oauth_client.client_id,
                "client_secret": self.oauth_client.client_secret,
                "scope": " ".join(self.oauth_client.scope),
                "redirect_uri": self.oauth_client.redirect_uris[0],
            },
        )

        access_token = res.json["access_token"]
        claims = jwt.decode(access_token, self.jwks)

        assert claims["auth_time"] == 1234
        assert claims["amr"] == "amr"
        assert claims["acr"] == "acr"


class JWTAccessTokenResourceServerTest(TestCase):
    def setUp(self):
        super().setUp()
        self.issuer = "https://authorization-server.example.org/"
        self.resource_server = "resource-server-id"
        self.jwks = read_file_path("jwks_private.json")
        self.token_validator = create_token_validator(
            self.issuer, self.resource_server, self.jwks
        )
        self.resource_protector = create_resource_protector(
            self.app, self.token_validator
        )
        self.user = create_user()
        self.oauth_client = create_oauth_client(self.resource_server, self.user)
        self.claims = create_access_token_claims(
            self.oauth_client, self.user, self.issuer
        )
        self.access_token = create_access_token(self.claims, self.jwks)
        self.token = create_token(self.access_token)

    def test_access_resource(self):
        headers = {"Authorization": f"Bearer {self.access_token}"}

        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["username"] == "foo"

    def test_missing_authorization(self):
        rv = self.client.get("/protected")
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "missing_authorization"

    def test_unsupported_token_type(self):
        headers = {"Authorization": "invalid token"}
        rv = self.client.get("/protected", headers=headers)
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"

    def test_invalid_token(self):
        headers = {"Authorization": "Bearer invalid"}
        rv = self.client.get("/protected", headers=headers)
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_typ(self):
        """The resource server MUST verify that the 'typ' header value is 'at+jwt' or
        'application/at+jwt' and reject tokens carrying any other value.
        """
        access_token = create_access_token(self.claims, self.jwks, typ="at+jwt")

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["username"] == "foo"

        access_token = create_access_token(
            self.claims, self.jwks, typ="application/at+jwt"
        )

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["username"] == "foo"

        access_token = create_access_token(self.claims, self.jwks, typ="invalid")

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_missing_required_claims(self):
        required_claims = ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
        for claim in required_claims:
            claims = create_access_token_claims(
                self.oauth_client, self.user, self.issuer
            )
            del claims[claim]
            access_token = create_access_token(claims, self.jwks)

            headers = {"Authorization": f"Bearer {access_token}"}
            rv = self.client.get("/protected", headers=headers)
            resp = json.loads(rv.data)
            assert resp["error"] == "invalid_token"

    def test_invalid_iss(self):
        """The issuer identifier for the authorization server (which is typically obtained
        during discovery) MUST exactly match the value of the 'iss' claim.
        """
        self.claims["iss"] = "invalid-issuer"
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_invalid_aud(self):
        """The resource server MUST validate that the 'aud' claim contains a resource
        indicator value corresponding to an identifier the resource server expects for
        itself. The JWT access token MUST be rejected if 'aud' does not contain a
        resource indicator of the current resource server as a valid audience.
        """
        self.claims["aud"] = "invalid-resource-indicator"
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_invalid_exp(self):
        """The current time MUST be before the time represented by the 'exp' claim.
        Implementers MAY provide for some small leeway, usually no more than a few
        minutes, to account for clock skew.
        """
        self.claims["exp"] = time.time() - 1
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_scope_restriction(self):
        """If an authorization request includes a scope parameter, the corresponding
        issued JWT access token SHOULD include a 'scope' claim as defined in Section
        4.2 of [RFC8693]. All the individual scope strings in the 'scope' claim MUST
        have meaning for the resources indicated in the 'aud' claim. See Section 5 for
        more considerations about the relationship between scope strings and resources
        indicated by the 'aud' claim.
        """
        self.claims["scope"] = ["invalid-scope"]
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["username"] == "foo"

        rv = self.client.get("/protected-by-scope", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "insufficient_scope"

    def test_entitlements_restriction(self):
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
            claims = create_access_token_claims(
                self.oauth_client, self.user, self.issuer
            )
            claims[claim] = ["invalid"]
            access_token = create_access_token(claims, self.jwks)

            headers = {"Authorization": f"Bearer {access_token}"}
            rv = self.client.get("/protected", headers=headers)
            resp = json.loads(rv.data)
            assert resp["username"] == "foo"

            rv = self.client.get(f"/protected-by-{claim}", headers=headers)
            resp = json.loads(rv.data)
            assert resp["error"] == "invalid_token"

    def test_extra_attributes(self):
        """Authorization servers MAY return arbitrary attributes not defined in any
        existing specification, as long as the corresponding claim names are collision
        resistant or the access tokens are meant to be used only within a private
        subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.
        """
        self.claims["email"] = "user@example.org"
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["token"]["email"] == "user@example.org"

    def test_invalid_auth_time(self):
        self.claims["auth_time"] = "invalid-auth-time"
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"

    def test_invalid_amr(self):
        self.claims["amr"] = "invalid-amr"
        access_token = create_access_token(self.claims, self.jwks)

        headers = {"Authorization": f"Bearer {access_token}"}
        rv = self.client.get("/protected", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"


class JWTAccessTokenIntrospectionTest(TestCase):
    def setUp(self):
        super().setUp()
        self.issuer = "https://authlib.org/"
        self.resource_server = "resource-server-id"
        self.jwks = read_file_path("jwks_private.json")
        self.authorization_server = create_authorization_server(self.app)
        self.authorization_server.register_grant(AuthorizationCodeGrant)
        self.introspection_endpoint = create_introspection_endpoint(
            self.app, self.authorization_server, self.issuer, self.jwks
        )
        self.user = create_user()
        self.oauth_client = create_oauth_client("client-id", self.user)
        self.claims = create_access_token_claims(
            self.oauth_client,
            self.user,
            self.issuer,
            aud=[self.resource_server],
        )
        self.access_token = create_access_token(self.claims, self.jwks)

    def test_introspection(self):
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": self.access_token}, headers=headers
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp["active"]
        assert resp["client_id"] == self.oauth_client.client_id
        assert resp["token_type"] == "Bearer"
        assert resp["scope"] == self.oauth_client.scope
        assert resp["sub"] == self.user.id
        assert resp["aud"] == [self.resource_server]
        assert resp["iss"] == self.issuer

    def test_introspection_username(self):
        self.introspection_endpoint.get_username = lambda user_id: db.session.get(
            User, user_id
        ).username

        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": self.access_token}, headers=headers
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp["active"]
        assert resp["username"] == self.user.username

    def test_non_access_token_skipped(self):
        class MyIntrospectionEndpoint(IntrospectionEndpoint):
            def query_token(self, token, token_type_hint):
                return None

        self.authorization_server.register_endpoint(MyIntrospectionEndpoint)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "refresh-token",
                "token_type_hint": "refresh_token",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert not resp["active"]

    def test_access_token_non_jwt_skipped(self):
        class MyIntrospectionEndpoint(IntrospectionEndpoint):
            def query_token(self, token, token_type_hint):
                return None

        self.authorization_server.register_endpoint(MyIntrospectionEndpoint)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "non-jwt-access-token",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert not resp["active"]

    def test_permission_denied(self):
        self.introspection_endpoint.check_permission = lambda *args: False

        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": self.access_token}, headers=headers
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert not resp["active"]

    def test_token_expired(self):
        self.claims["exp"] = time.time() - 3600
        access_token = create_access_token(self.claims, self.jwks)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": access_token}, headers=headers
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert not resp["active"]

    def test_introspection_different_issuer(self):
        class MyIntrospectionEndpoint(IntrospectionEndpoint):
            def query_token(self, token, token_type_hint):
                return None

        self.authorization_server.register_endpoint(MyIntrospectionEndpoint)

        self.claims["iss"] = "different-issuer"
        access_token = create_access_token(self.claims, self.jwks)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": access_token}, headers=headers
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert not resp["active"]

    def test_introspection_invalid_claim(self):
        self.claims["exp"] = "invalid"
        access_token = create_access_token(self.claims, self.jwks)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/introspect", data={"token": access_token}, headers=headers
        )
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_token"


class JWTAccessTokenRevocationTest(TestCase):
    def setUp(self):
        super().setUp()
        self.issuer = "https://authlib.org/"
        self.resource_server = "resource-server-id"
        self.jwks = read_file_path("jwks_private.json")
        self.authorization_server = create_authorization_server(self.app)
        self.authorization_server.register_grant(AuthorizationCodeGrant)
        self.revocation_endpoint = create_revocation_endpoint(
            self.app, self.authorization_server, self.issuer, self.jwks
        )
        self.user = create_user()
        self.oauth_client = create_oauth_client("client-id", self.user)
        self.claims = create_access_token_claims(
            self.oauth_client,
            self.user,
            self.issuer,
            aud=[self.resource_server],
        )
        self.access_token = create_access_token(self.claims, self.jwks)

    def test_revocation(self):
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/revoke", data={"token": self.access_token}, headers=headers
        )
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"

    def test_non_access_token_skipped(self):
        class MyRevocationEndpoint(RevocationEndpoint):
            def query_token(self, token, token_type_hint):
                return None

        self.authorization_server.register_endpoint(MyRevocationEndpoint)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "refresh-token",
                "token_type_hint": "refresh_token",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp == {}

    def test_access_token_non_jwt_skipped(self):
        class MyRevocationEndpoint(RevocationEndpoint):
            def query_token(self, token, token_type_hint):
                return None

        self.authorization_server.register_endpoint(MyRevocationEndpoint)
        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "non-jwt-access-token",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp == {}

    def test_revocation_different_issuer(self):
        self.claims["iss"] = "different-issuer"
        access_token = create_access_token(self.claims, self.jwks)

        headers = self.create_basic_header(
            self.oauth_client.client_id, self.oauth_client.client_secret
        )
        rv = self.client.post(
            "/oauth/revoke", data={"token": access_token}, headers=headers
        )
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"
