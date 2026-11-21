import pytest
from fastapi import FastAPI
from fastapi import Request
from fastapi.testclient import TestClient

from authlib.integrations.fastapi_oauth2.requests import FastApiJsonPayload
from authlib.integrations.fastapi_oauth2.requests import FastApiJsonRequest
from authlib.integrations.fastapi_oauth2.requests import FastApiOAuth2Payload
from authlib.integrations.fastapi_oauth2.requests import FastApiOAuth2Request
from authlib.integrations.fastapi_oauth2.requests import create_json_request
from authlib.integrations.fastapi_oauth2.requests import create_oauth2_request


@pytest.fixture
def app():
    return FastAPI()


@pytest.fixture
def client(app):
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def sample_request(client):
    with client:
        response = client.get("/test")
    return response


# ------------------------------------------------------------------
# FastApiOAuth2Payload
# ------------------------------------------------------------------


class TestFastApiOAuth2Payload:
    def test_data_without_form(self, client):
        @client.app.get("/test")
        async def endpoint(request: Request):
            payload = FastApiOAuth2Payload(request)

            assert payload.data["client_id"] == "test-client"
            assert payload.data["grant_type"] == "client_credentials"

            return {"ok": True}

        response = client.get(
            "/test",
            params={
                "client_id": "test-client",
                "grant_type": "client_credentials",
            },
        )

        assert response.status_code == 200

    def test_data_with_form(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            form = await request.form()
            payload = FastApiOAuth2Payload(request, form)

            assert payload.data["grant_type"] == "password"
            assert payload.data["username"] == "admin"

            return {"ok": True}

        response = client.post(
            "/test",
            data={
                "grant_type": "password",
                "username": "admin",
            },
        )

        assert response.status_code == 200

    def test_query_and_form_parameters_are_combined(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            form = await request.form()
            payload = FastApiOAuth2Payload(request, form)

            assert payload.data["client_id"] == "query-client"
            assert payload.data["grant_type"] == "password"

            return {"ok": True}

        response = client.post(
            "/test?client_id=query-client",
            data={"grant_type": "password"},
        )

        assert response.status_code == 200

    def test_datalist(self, client):
        @client.app.get("/test")
        async def endpoint(request: Request):
            payload = FastApiOAuth2Payload(request)

            assert payload.datalist["scope"] == ["openid", "profile"]

            return {"ok": True}

        response = client.get(
            "/test",
            params=[("scope", "openid"), ("scope", "profile")],
        )

        assert response.status_code == 200

    def test_datalist_is_cached(self, client):
        @client.app.get("/test")
        async def endpoint(request: Request):
            payload = FastApiOAuth2Payload(request)

            first = payload.datalist
            second = payload.datalist

            assert first is second

            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200


# ------------------------------------------------------------------
# FastApiOAuth2Request
# ------------------------------------------------------------------


class TestFastApiOAuth2Request:
    def test_initialization(self, client):
        @client.app.get("/test")
        async def endpoint(request: Request):
            oauth_request = FastApiOAuth2Request(request)

            assert oauth_request.method == "GET"
            assert oauth_request.uri.endswith("/test")
            assert oauth_request.args["client_id"] == "test-client"
            assert oauth_request.form is None
            assert isinstance(oauth_request.payload, FastApiOAuth2Payload)

            return {"ok": True}

        response = client.get("/test?client_id=test-client")

        assert response.status_code == 200

    def test_form_property(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            form = await request.form()
            oauth_request = FastApiOAuth2Request(request, form)

            assert oauth_request.form is form

            return {"ok": True}

        response = client.post("/test", data={"username": "admin"})

        assert response.status_code == 200


# ------------------------------------------------------------------
# create_oauth2_request
# ------------------------------------------------------------------


class TestCreateOAuth2Request:
    @pytest.mark.parametrize(
        "content_type",
        [
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ],
    )
    def test_parses_form_data(self, client, content_type):
        @client.app.post("/test")
        async def endpoint(request: Request):
            oauth_request = await create_oauth2_request(request)

            assert oauth_request.form is not None
            assert oauth_request.form["username"] == "admin"

            return {"ok": True}

        if content_type == "multipart/form-data":
            response = client.post(
                "/test",
                files={"username": (None, "admin")},
            )
        else:
            response = client.post(
                "/test",
                data={"username": "admin"},
            )

        assert response.status_code == 200

    def test_does_not_parse_form_for_json(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            oauth_request = await create_oauth2_request(request)

            assert oauth_request.form is None

            return {"ok": True}

        response = client.post("/test", json={"username": "admin"})

        assert response.status_code == 200

    def test_does_not_parse_form_for_get(self, client):
        @client.app.get("/test")
        async def endpoint(request: Request):
            oauth_request = await create_oauth2_request(request)

            assert oauth_request.form is None

            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200


# ------------------------------------------------------------------
# FastApiJsonPayload
# ------------------------------------------------------------------


class TestFastApiJsonPayload:
    def test_data(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            data = {"client_id": "test-client"}
            payload = FastApiJsonPayload(request, data)

            assert payload.data == data

            return {"ok": True}

        response = client.post("/test")

        assert response.status_code == 200

    def test_data_without_value(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            payload = FastApiJsonPayload(request)

            assert payload.data is None

            return {"ok": True}

        response = client.post("/test")

        assert response.status_code == 200


# ------------------------------------------------------------------
# FastApiJsonRequest
# ------------------------------------------------------------------


class TestFastApiJsonRequest:
    def test_initialization(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            data = {"grant_type": "client_credentials"}
            oauth_request = FastApiJsonRequest(request, data)

            assert oauth_request.method == "POST"
            assert oauth_request.uri.endswith("/test")
            assert isinstance(oauth_request.payload, FastApiJsonPayload)
            assert oauth_request.payload.data == data

            return {"ok": True}

        response = client.post("/test")

        assert response.status_code == 200


# ------------------------------------------------------------------
# create_json_request
# ------------------------------------------------------------------


class TestCreateJsonRequest:
    def test_parses_json(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            oauth_request = await create_json_request(request)

            assert oauth_request.payload.data == {
                "client_id": "test-client",
                "grant_type": "client_credentials",
            }

            return {"ok": True}

        response = client.post(
            "/test",
            json={
                "client_id": "test-client",
                "grant_type": "client_credentials",
            },
        )

        assert response.status_code == 200

    def test_invalid_json_returns_none(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            oauth_request = await create_json_request(request)

            assert oauth_request.payload.data is None

            return {"ok": True}

        response = client.post(
            "/test",
            content="invalid json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 200

    def test_empty_body_returns_none(self, client):
        @client.app.post("/test")
        async def endpoint(request: Request):
            oauth_request = await create_json_request(request)

            assert oauth_request.payload.data is None

            return {"ok": True}

        response = client.post("/test")

        assert response.status_code == 200
