import pytest

from authlib.oauth1.rfc5849 import errors
from tests.util import decode_response

from .models import User


def test_invalid_authorization(factory, server):
    url = "/oauth/authorize"
    request = factory.post(url)
    with pytest.raises(errors.MissingRequiredParameterError):
        server.check_authorization_request(request)

    request = factory.post(url, data={"oauth_token": "a"})
    with pytest.raises(errors.InvalidTokenError):
        server.check_authorization_request(request)


def test_invalid_initiate(factory, server):
    url = "/oauth/initiate"
    # Test with non-existent client
    request = factory.post(
        url,
        data={
            "oauth_consumer_key": "nonexistent",  # Client doesn't exist
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    resp = server.create_temporary_credentials_response(request)
    data = decode_response(resp.content)
    assert data["error"] == "invalid_client"


def test_authorize_denied(factory, plaintext_server):
    server = plaintext_server
    initiate_url = "/oauth/initiate"
    authorize_url = "/oauth/authorize"

    # case 1
    request = factory.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    resp = server.create_temporary_credentials_response(request)
    data = decode_response(resp.content)
    assert "oauth_token" in data

    request = factory.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    resp = server.create_authorization_response(request)
    assert resp.status_code == 302
    assert "access_denied" in resp["Location"]
    assert "https://client.test" in resp["Location"]

    # case 2
    request = factory.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "https://i.test",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    resp = server.create_temporary_credentials_response(request)
    data = decode_response(resp.content)
    assert "oauth_token" in data
    request = factory.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    resp = server.create_authorization_response(request)
    assert resp.status_code == 302
    assert "access_denied" in resp["Location"]
    assert "https://i.test" in resp["Location"]


def test_authorize_granted(factory, plaintext_server):
    server = plaintext_server
    user = User.objects.get(username="foo")
    initiate_url = "/oauth/initiate"
    authorize_url = "/oauth/authorize"

    # case 1
    request = factory.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "oob",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    resp = server.create_temporary_credentials_response(request)
    data = decode_response(resp.content)
    assert "oauth_token" in data

    request = factory.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    resp = server.create_authorization_response(request, user)
    assert resp.status_code == 302

    assert "oauth_verifier" in resp["Location"]
    assert "https://client.test" in resp["Location"]

    # case 2
    request = factory.post(
        initiate_url,
        data={
            "oauth_consumer_key": "client",
            "oauth_callback": "https://i.test",
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": "secret&",
        },
    )
    resp = server.create_temporary_credentials_response(request)
    data = decode_response(resp.content)
    assert "oauth_token" in data

    request = factory.post(authorize_url, data={"oauth_token": data["oauth_token"]})
    resp = server.create_authorization_response(request, user)

    assert resp.status_code == 302
    assert "oauth_verifier" in resp["Location"]
    assert "https://i.test" in resp["Location"]
