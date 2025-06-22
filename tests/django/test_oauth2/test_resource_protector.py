import json

from django.http import JsonResponse

from authlib.integrations.django_oauth2 import BearerTokenValidator
from authlib.integrations.django_oauth2 import ResourceProtector

from .models import Client
from .models import OAuth2Token
from .models import User
from .oauth2_server import TestCase

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))


class ResourceProtectorTest(TestCase):
    def prepare_data(self, expires_in=3600, scope="profile"):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            client_secret="secret",
            scope="profile",
        )
        client.save()

        token = OAuth2Token(
            user_id=user.pk,
            client_id=client.client_id,
            token_type="bearer",
            access_token="a1",
            scope=scope,
            expires_in=expires_in,
        )
        token.save()

    def test_invalid_token(self):
        @require_oauth("profile")
        def get_user_profile(request):
            user = request.oauth_token.user
            return JsonResponse(dict(sub=user.pk, username=user.username))

        self.prepare_data()

        request = self.factory.get("/user")
        resp = get_user_profile(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "missing_authorization"

        request = self.factory.get("/user", HTTP_AUTHORIZATION="invalid token")
        resp = get_user_profile(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "unsupported_token_type"

        request = self.factory.get("/user", HTTP_AUTHORIZATION="bearer token")
        resp = get_user_profile(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_token"

    def test_expired_token(self):
        self.prepare_data(-10)

        @require_oauth("profile")
        def get_user_profile(request):
            user = request.oauth_token.user
            return JsonResponse(dict(sub=user.pk, username=user.username))

        request = self.factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
        resp = get_user_profile(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_token"

    def test_insufficient_token(self):
        self.prepare_data()

        @require_oauth("email")
        def get_user_email(request):
            user = request.oauth_token.user
            return JsonResponse(dict(email=user.email))

        request = self.factory.get("/user/email", HTTP_AUTHORIZATION="bearer a1")
        resp = get_user_email(request)
        assert resp.status_code == 403
        data = json.loads(resp.content)
        assert data["error"] == "insufficient_scope"

    def test_access_resource(self):
        self.prepare_data()

        @require_oauth("profile", optional=True)
        def get_user_profile(request):
            if request.oauth_token:
                user = request.oauth_token.user
                return JsonResponse(dict(sub=user.pk, username=user.username))
            return JsonResponse(dict(sub=0, username="anonymous"))

        request = self.factory.get("/user")
        resp = get_user_profile(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["username"] == "anonymous"

        request = self.factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
        resp = get_user_profile(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["username"] == "foo"

    def test_scope_operator(self):
        self.prepare_data()

        @require_oauth(["profile email"])
        def operator_and(request):
            user = request.oauth_token.user
            return JsonResponse(dict(sub=user.pk, username=user.username))

        @require_oauth(["profile", "email"])
        def operator_or(request):
            user = request.oauth_token.user
            return JsonResponse(dict(sub=user.pk, username=user.username))

        request = self.factory.get("/user", HTTP_AUTHORIZATION="bearer a1")
        resp = operator_and(request)
        assert resp.status_code == 403
        data = json.loads(resp.content)
        assert data["error"] == "insufficient_scope"

        resp = operator_or(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["username"] == "foo"
