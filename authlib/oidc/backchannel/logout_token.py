"""Logout token creation for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

import time
import uuid

from joserfc import jwt
from joserfc.jwk import KeySet

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def create_logout_token(
    issuer: str,
    audience: str,
    key,
    algorithm: str = "RS256",
    sub: str | None = None,
    sid: str | None = None,
    expires_in: int = 120,
) -> str:
    """Create a signed logout token JWT.

    :param issuer: The OP's issuer identifier.
    :param audience: The client_id of the RP being notified.
    :param key: The signing key (joserfc Key, KeySet, or JWKS dict).
    :param algorithm: JWT signing algorithm.
    :param sub: Subject identifier. Required if ``sid`` is not provided.
    :param sid: Session ID. Required if ``sub`` is not provided.
    :param expires_in: Token lifetime in seconds. Spec recommends at most 120.
    :raises ValueError: If neither ``sub`` nor ``sid`` is provided.
    """
    # backchannel §2.4: "A Logout Token MUST contain either a sub or a sid
    # Claim, and MAY contain both."
    if sub is None and sid is None:
        raise ValueError("At least one of 'sub' or 'sid' must be provided")

    now = int(time.time())
    payload: dict = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
        # backchannel §2.4: "events - [...] whose value is a JSON object
        # containing the member name
        # http://schemas.openid.net/event/backchannel-logout"
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }

    if sub is not None:
        payload["sub"] = sub
    if sid is not None:
        payload["sid"] = sid

    # backchannel §2.4: "The typ JOSE header parameter [...] SHOULD be
    # logout+jwt"
    header = {"alg": algorithm, "typ": "logout+jwt"}

    if isinstance(key, dict):
        key = KeySet.import_key_set(key)  # type: ignore[arg-type]

    return jwt.encode(header, payload, key)
