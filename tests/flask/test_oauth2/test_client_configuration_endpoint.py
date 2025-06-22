from flask import json

from authlib.oauth2.rfc7592 import (
    ClientConfigurationEndpoint as _ClientConfigurationEndpoint,
)

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ClientConfigurationEndpoint(_ClientConfigurationEndpoint):
    software_statement_alg_values_supported = ["RS256"]

    def authenticate_token(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header:
            access_token = auth_header.split()[1]
            return Token.query.filter_by(access_token=access_token).first()

    def update_client(self, client, client_metadata, request):
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        return client

    def authenticate_client(self, request):
        client_id = request.uri.split("/")[-1]
        return Client.query.filter_by(client_id=client_id).first()

    def revoke_access_token(self, request, token):
        token.revoked = True
        db.session.add(token)
        db.session.commit()

    def check_permission(self, client, request):
        client_id = request.uri.split("/")[-1]
        return client_id != "unauthorized_client_id"

    def delete_client(self, client, request):
        db.session.delete(client)
        db.session.commit()

    def generate_client_registration_info(self, client, request):
        return {
            "registration_client_uri": request.uri,
            "registration_access_token": request.headers["Authorization"].split(" ")[1],
        }


class ClientConfigurationTestMixin(TestCase):
    def prepare_data(self, endpoint_cls=None, metadata=None):
        app = self.app
        server = create_authorization_server(app)

        if endpoint_cls:
            server.register_endpoint(endpoint_cls)
        else:

            class MyClientConfiguration(ClientConfigurationEndpoint):
                def get_server_metadata(self):
                    return metadata

            server.register_endpoint(MyClientConfiguration)

        @app.route("/configure_client/<client_id>", methods=["PUT", "GET", "DELETE"])
        def configure_client(client_id):
            return server.create_endpoint_response(
                ClientConfigurationEndpoint.ENDPOINT_NAME
            )

        user = User(username="foo")
        db.session.add(user)

        client = Client(
            client_id="client_id",
            client_secret="client_secret",
        )
        client.set_client_metadata(
            {
                "client_name": "Authlib",
                "scope": "openid profile",
            }
        )
        db.session.add(client)

        token = Token(
            user_id=user.id,
            client_id=client.id,
            token_type="bearer",
            access_token="a1",
            refresh_token="r1",
            scope="openid profile",
            expires_in=3600,
        )
        db.session.add(token)

        db.session.commit()
        return user, client, token


class ClientConfigurationReadTest(ClientConfigurationTestMixin):
    def test_read_client(self):
        user, client, token = self.prepare_data()
        assert client.client_name == "Authlib"
        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.get("/configure_client/client_id", headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["client_id"] == client.client_id
        assert resp["client_name"] == "Authlib"
        assert (
            resp["registration_client_uri"]
            == "http://localhost/configure_client/client_id"
        )
        assert resp["registration_access_token"] == token.access_token

    def test_access_denied(self):
        user, client, token = self.prepare_data()
        rv = self.client.get("/configure_client/client_id")
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer invalid_token"}
        rv = self.client.get("/configure_client/client_id", headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer unauthorized_token"}
        rv = self.client.get(
            "/configure_client/client_id",
            json={"client_id": "client_id", "client_name": "new client_name"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

    def test_invalid_client(self):
        # If the client does not exist on this server, the server MUST respond
        # with HTTP 401 Unauthorized, and the registration access token used to
        # make this request SHOULD be immediately revoked.
        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.get("/configure_client/invalid_client_id", headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 401
        assert resp["error"] == "invalid_client"

    def test_unauthorized_client(self):
        # If the client does not have permission to read its record, the server
        # MUST return an HTTP 403 Forbidden.

        client = Client(
            client_id="unauthorized_client_id",
            client_secret="unauthorized_client_secret",
        )
        db.session.add(client)

        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.get(
            "/configure_client/unauthorized_client_id", headers=headers
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 403
        assert resp["error"] == "unauthorized_client"


class ClientConfigurationUpdateTest(ClientConfigurationTestMixin):
    def test_update_client(self):
        # Valid values of client metadata fields in this request MUST replace,
        # not augment, the values previously associated with this client.
        # Omitted fields MUST be treated as null or empty values by the server,
        # indicating the client's request to delete them from the client's
        # registration.  The authorization server MAY ignore any null or empty
        # value in the request just as any other value.

        user, client, token = self.prepare_data()
        assert client.client_name == "Authlib"
        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": client.client_id,
            "client_name": "NewAuthlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 200
        assert resp["client_id"] == client.client_id
        assert resp["client_name"] == "NewAuthlib"
        assert client.client_name == "NewAuthlib"
        assert client.scope == ""

    def test_access_denied(self):
        user, client, token = self.prepare_data()
        rv = self.client.put("/configure_client/client_id", json={})
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer invalid_token"}
        rv = self.client.put("/configure_client/client_id", json={}, headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer unauthorized_token"}
        rv = self.client.put(
            "/configure_client/client_id",
            json={"client_id": "client_id", "client_name": "new client_name"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

    def test_invalid_request(self):
        user, client, token = self.prepare_data()
        headers = {"Authorization": f"bearer {token.access_token}"}

        # The client MUST include its 'client_id' field in the request...
        rv = self.client.put("/configure_client/client_id", json={}, headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "invalid_request"

        # ... and it MUST be the same as its currently issued client identifier.
        rv = self.client.put(
            "/configure_client/client_id",
            json={"client_id": "invalid_client_id"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "invalid_request"

        # The updated client metadata fields request MUST NOT include the
        # 'registration_access_token', 'registration_client_uri',
        # 'client_secret_expires_at', or 'client_id_issued_at' fields
        rv = self.client.put(
            "/configure_client/client_id",
            json={
                "client_id": "client_id",
                "registration_client_uri": "https://foobar.com",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "invalid_request"

        # If the client includes the 'client_secret' field in the request,
        # the value of this field MUST match the currently issued client
        # secret for that client.
        rv = self.client.put(
            "/configure_client/client_id",
            json={"client_id": "client_id", "client_secret": "invalid_secret"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "invalid_request"

    def test_invalid_client(self):
        # If the client does not exist on this server, the server MUST respond
        # with HTTP 401 Unauthorized, and the registration access token used to
        # make this request SHOULD be immediately revoked.
        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.put(
            "/configure_client/invalid_client_id",
            json={"client_id": "invalid_client_id", "client_name": "new client_name"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 401
        assert resp["error"] == "invalid_client"

    def test_unauthorized_client(self):
        # If the client does not have permission to read its record, the server
        # MUST return an HTTP 403 Forbidden.

        client = Client(
            client_id="unauthorized_client_id",
            client_secret="unauthorized_client_secret",
        )
        db.session.add(client)

        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.put(
            "/configure_client/unauthorized_client_id",
            json={
                "client_id": "unauthorized_client_id",
                "client_name": "new client_name",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 403
        assert resp["error"] == "unauthorized_client"

    def test_invalid_metadata(self):
        metadata = {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        user, client, token = self.prepare_data(metadata=metadata)
        headers = {"Authorization": f"bearer {token.access_token}"}

        # For all metadata fields, the authorization server MAY replace any
        # invalid values with suitable default values, and it MUST return any
        # such fields to the client in the response.
        # If the client attempts to set an invalid metadata field and the
        # authorization server does not set a default value, the authorization
        # server responds with an error as described in [RFC7591].

        body = {
            "client_id": client.client_id,
            "client_name": "NewAuthlib",
            "token_endpoint_auth_method": "invalid_auth_method",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "invalid_client_metadata"

    def test_scopes_supported(self):
        metadata = {"scopes_supported": ["profile", "email"]}
        user, client, token = self.prepare_data(metadata=metadata)

        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": "client_id",
            "scope": "profile email",
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_id"] == "client_id"
        assert resp["client_name"] == "Authlib"
        assert resp["scope"] == "profile email"

        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": "client_id",
            "scope": "",
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_id"] == "client_id"
        assert resp["client_name"] == "Authlib"

        body = {
            "client_id": "client_id",
            "scope": "profile email address",
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_response_types_supported(self):
        metadata = {"response_types_supported": ["code"]}
        user, client, token = self.prepare_data(metadata=metadata)

        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": "client_id",
            "response_types": ["code"],
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_id"] == "client_id"
        assert resp["client_name"] == "Authlib"
        assert resp["response_types"] == ["code"]

        # https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
        # If omitted, the default is that the client will use only the "code"
        # response type.
        body = {"client_id": "client_id", "client_name": "Authlib"}
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert "response_types" not in resp

        body = {
            "client_id": "client_id",
            "response_types": ["code", "token"],
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_grant_types_supported(self):
        metadata = {"grant_types_supported": ["authorization_code", "password"]}
        user, client, token = self.prepare_data(metadata=metadata)

        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": "client_id",
            "grant_types": ["password"],
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_id"] == "client_id"
        assert resp["client_name"] == "Authlib"
        assert resp["grant_types"] == ["password"]

        # https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
        # If omitted, the default behavior is that the client will use only
        # the "authorization_code" Grant Type.
        body = {"client_id": "client_id", "client_name": "Authlib"}
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert "grant_types" not in resp

        body = {
            "client_id": "client_id",
            "grant_types": ["client_credentials"],
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_token_endpoint_auth_methods_supported(self):
        metadata = {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        user, client, token = self.prepare_data(metadata=metadata)

        headers = {"Authorization": f"bearer {token.access_token}"}
        body = {
            "client_id": "client_id",
            "token_endpoint_auth_method": "client_secret_basic",
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_id"] == "client_id"
        assert resp["client_name"] == "Authlib"
        assert resp["token_endpoint_auth_method"] == "client_secret_basic"

        body = {
            "client_id": "client_id",
            "token_endpoint_auth_method": "none",
            "client_name": "Authlib",
        }
        rv = self.client.put("/configure_client/client_id", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"


class ClientConfigurationDeleteTest(ClientConfigurationTestMixin):
    def test_delete_client(self):
        user, client, token = self.prepare_data()
        assert client.client_name == "Authlib"
        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.delete("/configure_client/client_id", headers=headers)
        assert rv.status_code == 204
        assert not rv.data

    def test_access_denied(self):
        user, client, token = self.prepare_data()
        rv = self.client.delete("/configure_client/client_id")
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer invalid_token"}
        rv = self.client.delete("/configure_client/client_id", headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

        headers = {"Authorization": "bearer unauthorized_token"}
        rv = self.client.delete(
            "/configure_client/client_id",
            json={"client_id": "client_id", "client_name": "new client_name"},
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 400
        assert resp["error"] == "access_denied"

    def test_invalid_client(self):
        # If the client does not exist on this server, the server MUST respond
        # with HTTP 401 Unauthorized, and the registration access token used to
        # make this request SHOULD be immediately revoked.
        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.delete("/configure_client/invalid_client_id", headers=headers)
        resp = json.loads(rv.data)
        assert rv.status_code == 401
        assert resp["error"] == "invalid_client"

    def test_unauthorized_client(self):
        # If the client does not have permission to read its record, the server
        # MUST return an HTTP 403 Forbidden.

        client = Client(
            client_id="unauthorized_client_id",
            client_secret="unauthorized_client_secret",
        )
        db.session.add(client)

        user, client, token = self.prepare_data()

        headers = {"Authorization": f"bearer {token.access_token}"}
        rv = self.client.delete(
            "/configure_client/unauthorized_client_id", headers=headers
        )
        resp = json.loads(rv.data)
        assert rv.status_code == 403
        assert resp["error"] == "unauthorized_client"
