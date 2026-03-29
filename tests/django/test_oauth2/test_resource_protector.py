import json

import pytest
from django.http import JsonResponse

from authlib.integrations.django_oauth2 import BearerTokenValidator
from authlib.integrations.django_oauth2 import ResourceProtector

from .models import Client
from .models import OAuth2Token

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))


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
    assert data["error"] == "missing_authorization"

    request = factory.get("/user", HTTP_AUTHORIZATION="invalid token")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "unsupported_token_type"

    request = factory.get("/user", HTTP_AUTHORIZATION="bearer token")
    resp = get_user_profile(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_token"


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
