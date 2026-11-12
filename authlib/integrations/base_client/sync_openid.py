import time

from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oauth2.claims import JWTClaims
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo

from .errors import OAuthError


class _SignedUserInfo(JWTClaims):
    """Claims of a UserInfo response returned as a signed JWT."""

    REGISTERED_CLAIMS = JWTClaims.REGISTERED_CLAIMS + [
        claim
        for claim in UserInfo.REGISTERED_CLAIMS
        if claim not in JWTClaims.REGISTERED_CLAIMS
    ]


def _get_algorithms(metadata, name):
    """Return the algorithms of the name_signing_alg_values_supported
    metadata, without none.
    """
    algorithms = metadata.get(f"{name}_signing_alg_values_supported") or []
    if isinstance(algorithms, str):
        algorithms = [algorithms]

    return [alg for alg in algorithms if alg != "none"]


def _get_id_token_algorithms(metadata):
    """Return the algorithms accepted for the ID token signature."""
    # Per OpenID Connect Registration §2, a client receives RS256 ID tokens
    # by default.
    return _get_algorithms(metadata, "id_token") or ["RS256"]


def _get_userinfo_algorithms(metadata):
    """Return the algorithms accepted for the UserInfo response signature.

    Without metadata, the default algorithms of joserfc are accepted.
    """
    alg = metadata.get("userinfo_signed_response_alg")
    if alg and alg != "none":
        return [alg]

    return _get_algorithms(metadata, "userinfo") or None


def _is_jwt_response(resp):
    """Tell whether the response is a JWT."""
    content_type = resp.headers.get("Content-Type", "")
    return content_type.split(";")[0].strip().lower() == "application/jwt"


def _parse_json_userinfo(resp, metadata):
    """Return the claims of a JSON UserInfo response."""
    # Per OpenID Connect Registration §2, if userinfo_signed_response_alg is
    # specified, the response will be JWT serialized.
    if metadata.get("userinfo_signed_response_alg", "none") != "none":
        raise OAuthError(description="The UserInfo response is not signed.")

    return UserInfo(resp.json())


def _validate_signed_userinfo(token, metadata, client_id, leeway=120):
    """Validate the claims of a signed UserInfo response."""
    # Per OpenID Connect Core §5.3.2, the sub Claim MUST always be returned
    # in the UserInfo Response. If signed, the UserInfo Response MUST contain
    # the Claims iss (issuer) and aud (audience) as members. The iss value
    # MUST be the OP's Issuer Identifier URL. The aud value MUST be or
    # include the RP's Client ID value.
    options = {
        "sub": {"essential": True},
        "iss": {"essential": True},
        "aud": {"essential": True},
    }
    if metadata.get("issuer"):
        options["iss"]["values"] = [metadata["issuer"]]

    if client_id:
        options["aud"]["values"] = [client_id]

    claims = _SignedUserInfo(token.claims, token.header, options)
    claims.validate(leeway=leeway)
    return UserInfo(claims)


def _check_userinfo_sub(userinfo, token):
    """Check that the sub of the UserInfo response is the sub of the ID token.

    The ID token claims are in the userinfo key of the token returned by
    authorize_access_token. Without them, there is nothing to compare.
    """
    claims = token.get("userinfo") if token else None
    if not claims or "sub" not in claims:
        return

    # Per OpenID Connect Core §5.3.2, the sub Claim in the UserInfo Response
    # MUST be verified to exactly match the sub Claim in the ID Token; if they
    # do not match, the UserInfo Response values MUST NOT be used.
    if userinfo.get("sub") != claims["sub"]:
        raise OAuthError(
            description="The UserInfo sub does not match the ID token sub."
        )


def _get_claims_options(claims_options, metadata):
    """Add the issuer check to the claims options, unless they check the
    issuer themselves.
    """
    claims_options = {
        key: dict(option) for key, option in (claims_options or {}).items()
    }
    issuer = metadata.get("issuer")
    if not issuer:
        return claims_options

    iss = claims_options.setdefault("iss", {})
    if not {"value", "values", "validate"} & iss.keys():
        iss["values"] = [issuer]

    return claims_options


def _may_refresh_jwk_set(client):
    """Tell if the JWK set can be fetched again for an unknown ``kid``, at
    most once per ``jwks_refresh_interval`` seconds.
    """
    now = time.monotonic()
    refreshed_at = client._jwk_set_refreshed_at
    if refreshed_at is not None and now - refreshed_at < client.jwks_refresh_interval:
        return False

    client._jwk_set_refreshed_at = now
    return True


class OpenIDMixin:
    #: Minimum number of seconds between two fetches of the JWK set caused by
    #: an ID token or a signed UserInfo response with an unknown ``kid``.
    jwks_refresh_interval = 60
    _jwk_set_refreshed_at = None

    def fetch_jwk_set(self, force=False):
        metadata = self.load_server_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        with self._get_session() as session:
            resp = session.request("GET", uri, withhold_token=True)
            resp.raise_for_status()
            jwk_set = resp.json()

        self.server_metadata["jwks"] = jwk_set
        return jwk_set

    def _decode_jwt(self, value, metadata, algorithms):
        """Decode a JWT signed with a key of the provider JWK set."""
        registry = JWSRegistry(algorithms=algorithms, strict_check_header=False)
        key_set = KeySet.import_key_set(self.fetch_jwk_set())
        try:
            return jwt.decode(value, key=key_set, registry=registry)
        except InvalidKeyIdError:
            if metadata.get("jwks_uri") and not _may_refresh_jwk_set(self):
                raise

        key_set = KeySet.import_key_set(self.fetch_jwk_set(force=True))
        return jwt.decode(value, key=key_set, registry=registry)

    def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``.

        When the response is a signed JWT (OpenID Connect Core §5.3.2), its
        signature is verified with the provider JWK set, and its ``sub``,
        ``iss`` and ``aud`` claims are validated. When the client registered
        ``userinfo_signed_response_alg``, the response must be signed with
        this algorithm.

        The ``sub`` of the response must be the ``sub`` of the ID token
        (OpenID Connect Core §5.3.2). The ID token claims come from the token
        returned by ``authorize_access_token``.
        """
        metadata = self.load_server_metadata()
        token = kwargs.pop("token", None)
        if token is None:
            token = self._get_requested_token(kwargs.get("request"))

        resp = self.get(metadata["userinfo_endpoint"], token=token, **kwargs)
        resp.raise_for_status()
        if _is_jwt_response(resp):
            decoded = self._decode_jwt(
                resp.text, metadata, _get_userinfo_algorithms(metadata)
            )
            userinfo = _validate_signed_userinfo(decoded, metadata, self.client_id)
        else:
            userinfo = _parse_json_userinfo(resp, metadata)

        _check_userinfo_sub(userinfo, token)
        return userinfo

    def parse_id_token(
        self, token, nonce, claims_options=None, claims_cls=None, leeway=120
    ):
        """Return UserInfo after validating the token's ``id_token``.

        The expected ``nonce`` is controlled by the application. Token claims
        such as ``nonce_supported`` cannot disable its validation.
        """
        if "id_token" not in token:
            return None

        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )

        if claims_cls is None:
            if "access_token" in token:
                claims_params["access_token"] = token["access_token"]
                claims_cls = CodeIDToken
            else:
                claims_cls = ImplicitIDToken

        metadata = self.load_server_metadata()
        claims_options = _get_claims_options(claims_options, metadata)
        alg_values = _get_id_token_algorithms(metadata)

        token = self._decode_jwt(token["id_token"], metadata, alg_values)
        claims = claims_cls(token.claims, token.header, claims_options, claims_params)
        claims.validate(leeway=leeway)
        return UserInfo(claims)

    def create_logout_url(
        self,
        post_logout_redirect_uri=None,
        id_token_hint=None,
        state=None,
        **kwargs,
    ):
        """Generate the end session URL for RP-Initiated Logout.

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param state: Opaque value for maintaining state.
        :param kwargs: Extra parameters (client_id, logout_hint, ui_locales).
        :return: dict with 'url' and 'state' keys.
        """
        metadata = self.load_server_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if not end_session_endpoint:
            raise RuntimeError('Missing "end_session_endpoint" in metadata')

        params = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
            if state is None:
                state = generate_token(20)
            params["state"] = state

        for key in ("client_id", "logout_hint", "ui_locales"):
            if key in kwargs:
                params[key] = kwargs[key]

        url = add_params_to_uri(end_session_endpoint, params)
        return {"url": url, "state": state}
