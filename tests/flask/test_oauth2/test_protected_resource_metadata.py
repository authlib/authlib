import pytest
from flask import jsonify

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.oauth2.rfc9728 import ProtectedResourceMetadata
from authlib.oauth2.rfc9728 import ResourceMetadataExtension
from authlib.oauth2.rfc9728 import get_well_known_url

from .models import Token
from .oauth2_server import create_bearer_header

RESOURCE_METADATA_URL = "https://resource.test/.well-known/oauth-protected-resource"


@pytest.fixture(autouse=True)
def resource_server(app, db):
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test"})
    require_oauth = ResourceProtector()
    require_oauth.register_extension(ResourceMetadataExtension(metadata))
    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(BearerTokenValidator())

    @app.route("/user")
    @require_oauth("profile")
    def user_profile():
        return jsonify(status="ok")

    class PerRouteExtension(ResourceMetadataExtension):
        def get_resource_metadata_url(self, request):
            return get_well_known_url(request.uri, external=True)

    require_oauth_per_route = ResourceProtector()
    require_oauth_per_route.register_extension(PerRouteExtension(metadata))
    require_oauth_per_route.register_token_validator(BearerTokenValidator())

    @app.route("/api/items")
    @require_oauth_per_route("profile")
    def items():
        return jsonify(status="ok")

    return require_oauth


def test_missing_token(test_client):
    """A request without token gets the resource_metadata URL in WWW-Authenticate."""
    rv = test_client.get("/user")
    assert rv.status_code == 401
    assert "error" not in rv.json
    assert rv.headers["Content-Type"] == "application/json"
    assert (
        f'resource_metadata="{RESOURCE_METADATA_URL}"' in rv.headers["WWW-Authenticate"]
    )


def test_invalid_token(test_client):
    """A request with an invalid token gets the resource_metadata URL and the error."""
    rv = test_client.get("/user", headers=create_bearer_header("invalid"))
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_token"
    www_authenticate = rv.headers["WWW-Authenticate"]
    assert f'resource_metadata="{RESOURCE_METADATA_URL}"' in www_authenticate
    assert 'error="invalid_token"' in www_authenticate


def test_resource_metadata_url_per_route(test_client):
    """get_resource_metadata_url can send a different URL for each route."""
    rv = test_client.get("/api/items")
    assert rv.status_code == 401
    assert (
        'resource_metadata="http://localhost/.well-known/oauth-protected-resource/api/items"'
        in rv.headers["WWW-Authenticate"]
    )
