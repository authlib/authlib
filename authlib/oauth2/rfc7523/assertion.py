import time
from typing import Any

from joserfc import jwt
from joserfc._rfc7517.models import BaseKey

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token


def set_jwt_header_parameter_from_key(
    header: dict[str, Any], key: Any, parameter_name: str
) -> None:
    """
    Copy a JWK parameter (e.g. alg, kid) from key into header.

    The key's value is an enforced constraint and takes priority over any
    value already present in header.
    """
    if isinstance(key, BaseKey):
        parameter_value = key.get(parameter_name)
        if parameter_value:
            header[parameter_name] = parameter_value


def sign_jwt_bearer_assertion(
    key,
    issuer,
    audience,
    subject=None,
    issued_at=None,
    expires_at=None,
    claims=None,
    header=None,
    **kwargs,
):
    _key = import_any_key(key)

    if header is None:
        header = {}
    alg = kwargs.pop("alg", None)
    if alg:
        header["alg"] = alg
    set_jwt_header_parameter_from_key(header=header, key=_key, parameter_name="alg")
    if "alg" not in header:
        raise ValueError("Missing 'alg' in header")

    set_jwt_header_parameter_from_key(header=header, key=_key, parameter_name="kid")

    payload = {"iss": issuer, "aud": audience}

    # subject is not required in Google service
    if subject:
        payload["sub"] = subject

    if not issued_at:
        issued_at = int(time.time())

    expires_in = kwargs.pop("expires_in", 3600)
    if expires_at is None:
        expires_at = issued_at + expires_in

    payload["iat"] = issued_at
    payload["exp"] = expires_at

    if claims:
        payload.update(claims)

    return jwt.encode(header, payload, _key, algorithms=[header["alg"]])


def client_secret_jwt_sign(
    client_secret, client_id, token_endpoint, alg="HS256", claims=None, **kwargs
):
    return _sign(client_secret, client_id, token_endpoint, alg, claims, **kwargs)


def private_key_jwt_sign(
    private_key, client_id, token_endpoint, alg="RS256", claims=None, **kwargs
):
    return _sign(private_key, client_id, token_endpoint, alg, claims, **kwargs)


def _sign(key, client_id, token_endpoint, alg, claims=None, **kwargs):
    # REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
    issuer = client_id
    # REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
    subject = client_id
    # The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
    audience = token_endpoint

    # jti is required
    if claims is None:
        claims = {}
    if "jti" not in claims:
        claims["jti"] = generate_token(36)

    return sign_jwt_bearer_assertion(
        key=key,
        issuer=issuer,
        audience=audience,
        subject=subject,
        claims=claims,
        alg=alg,
        **kwargs,
    )
