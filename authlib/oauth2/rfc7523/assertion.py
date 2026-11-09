import time

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token


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
    header = dict(header or {})
    alg = kwargs.pop("alg", None)
    if alg:
        header["alg"] = alg
    if "alg" not in header:
        raise ValueError("Missing 'alg' in header")

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

    # jti uniquely identifies the JWT and prevents replay attacks (RFC 7523 §3)
    payload["jti"] = generate_token(36)

    if claims:
        payload.update(claims)

    key = import_any_key(key)
    # Per OpenID Connect Core §10.1, a kid value MUST be provided when the
    # JWK Set of the signer has several keys.
    kid = getattr(key, "kid", None)
    if kid and "kid" not in header:
        header["kid"] = kid

    return jwt.encode(header, payload, key, algorithms=[header["alg"]])


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
    # Audience. RFC 7523 Section 3 allows the token endpoint URL; RFC 10070
    # tightens this: for client authentication the "aud" claim value MUST
    # use the issuer identifier of the authorization server as its sole
    # value. Pass ``issuer_id`` to comply; the token endpoint remains the
    # default for backwards compatibility.
    issuer_id = kwargs.pop("issuer_id", None)
    if issuer_id is not None:
        audience = issuer_id
        # Client authentication JWTs SHOULD be explicitly typed
        # (:rfc:`10070` updates :rfc:`7523` Section 3.2). Only added when
        # the tightened audience is used, so the type signal stays truthful.
        header = dict(kwargs.pop("header", None) or {})
        header.setdefault("typ", "client-authentication+jwt")
        kwargs["header"] = header
    else:
        audience = token_endpoint

    return sign_jwt_bearer_assertion(
        key=key,
        issuer=issuer,
        audience=audience,
        subject=subject,
        claims=claims,
        alg=alg,
        **kwargs,
    )
