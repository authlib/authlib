import json

import pytest
from django.http import JsonResponse

from authlib.integrations.django_oauth2 import BearerTokenValidator
from authlib.integrations.django_oauth2 import ResourceProtector
from authlib.oauth2.rfc9728 import ProtectedResourceMetadata
from authlib.oauth2.rfc9728 import ResourceMetadataExtension

from .models import Client
from .models import OAuth2Token

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))

RESOURCE_METADATA_URL = "https://resource.test/.well-known/oauth-protected-resource"
require_oauth_with_metadata = ResourceProtector()
require_oauth_with_metadata.register_token_validator(BearerTokenValidator(OAuth2Token))
require_oauth_with_metadata.register_extension(
    ResourceMetadataExtension(
        ProtectedResourceMetadata({"resource": "https://resource.test"})
    )
)


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        scope="profile",
    )
    client.save()
    yield client
    client.delete()


def test_invalid_token(factory):
    @require_oauth("profile")
    def get_user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    request = factory.get("/user")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert "error" not in data
    assert resp["WWW-Authenticate"] == "Bearer"

    request = factory.get("/user", HTTP_AUTHORIZATION="invalid token")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert "error" not in data
    assert resp["WWW-Authenticate"] == "Bearer"

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer token")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_token"


def test_error_response_headers(factory):
    """The error response has a single Content-Type and a WWW-Authenticate header."""

    @require_oauth("profile")
    def get_user_profile(request):
        return JsonResponse({})

    request = factory.get("/user")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    assert resp["Content-Type"] == "application/json"
    assert "WWW-Authenticate" in resp


def test_expired_token(factory, token):
    token.expires_in = -10
    token.save()

    @require_oauth("profile")
    def get_user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_token"


def test_insufficient_token(factory, token):
    @require_oauth("email")
    def get_user_email(request):
        user = request.oauth_token.user
        return JsonResponse(dict(email=user.email))

    request = factory.get("/user/email", HTTP_AUTHORIZATION="bearer a1")
    resp = get_user_email(request)
    assert resp.status_code == 403
    data = json.loads(resp.content)
    assert data["error"] == "insufficient_scope"


def test_access_resource(factory, token):
    @require_oauth("profile", optional=True)
    def get_user_profile(request):
        if request.oauth_token:
            user = request.oauth_token.user
            return JsonResponse(dict(sub=user.pk, username=user.username))
        return JsonResponse(dict(sub=0, username="anonymous"))

    request = factory.get("/user")
    resp = get_user_profile(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert data["username"] == "anonymous"

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
    resp = get_user_profile(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert data["username"] == "foo"


def test_scope_operator(factory, token):
    @require_oauth(["profile email"])
    def operator_and(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    @require_oauth(["profile", "email"])
    def operator_or(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
    resp = operator_and(request)
    assert resp.status_code == 403
    data = json.loads(resp.content)
    assert data["error"] == "insufficient_scope"

    resp = operator_or(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert data["username"] == "foo"


def test_decorator_without_parentheses(factory, token):
    @require_oauth
    def get_resource(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

    request = factory.get("/resource")
    resp = get_resource(request)
    assert resp.status_code == 401

    request = factory.get("/resource", HTTP_AUTHORIZATION="bearer a1")
    resp = get_resource(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert data["username"] == "foo"


def test_resource_metadata_in_error_response(factory):
    """The 401 response has the resource_metadata URL and a single Content-Type."""

    @require_oauth_with_metadata("profile")
    def get_user_profile(request):
        return JsonResponse({})

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer invalid")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    assert resp["Content-Type"] == "application/json"
    www_authenticate = resp["WWW-Authenticate"]
    assert f'resource_metadata="{RESOURCE_METADATA_URL}"' in www_authenticate
    assert 'error="invalid_token"' in www_authenticate
