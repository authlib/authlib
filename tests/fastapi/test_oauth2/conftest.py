import pytest

from authlib.integrations.fastapi_oauth2.authorization_server import AuthorizationServer


@pytest.fixture
def config():
    return {
        "OAUTH2_SCOPES_SUPPORTED": ["openid", "profile", "email"],
        "OAUTH2_ACCESS_TOKEN_GENERATOR": True,
        "OAUTH2_REFRESH_TOKEN_GENERATOR": False,
        "OAUTH2_TOKEN_EXPIRES_IN": {
            "authorization_code": 3600,
            "client_credentials": 1800,
        },
    }


@pytest.fixture
def query_client():
    return lambda client_id: {"client_id": client_id}


@pytest.fixture
def save_token():
    return lambda token, request: None


@pytest.fixture
def server(config, query_client, save_token):
    return AuthorizationServer(
        config=config,
        query_client=query_client,
        save_token=save_token,
    )
