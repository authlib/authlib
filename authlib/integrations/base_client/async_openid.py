from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo

from .async_app import _get_requested_token
from .sync_openid import _check_userinfo_sub
from .sync_openid import _get_claims_options
from .sync_openid import _get_id_token_algorithms
from .sync_openid import _get_userinfo_algorithms
from .sync_openid import _is_jwt_response
from .sync_openid import _may_refresh_jwk_set
from .sync_openid import _parse_json_userinfo
from .sync_openid import _validate_signed_userinfo

__all__ = ["AsyncOpenIDMixin"]


class AsyncOpenIDMixin:
    #: Minimum number of seconds between two fetches of the JWK set caused by
    #: an ID token or a signed UserInfo response with an unknown ``kid``.
    jwks_refresh_interval = 60
    _jwk_set_refreshed_at = None

    async def fetch_jwk_set(self, force=False):
        metadata = await self.load_server_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        async with self._get_session() as client:
            resp = await client.request("GET", uri, withhold_token=True)
            resp.raise_for_status()
            jwk_set = resp.json()

        self.server_metadata["jwks"] = jwk_set
        return jwk_set

    async def _decode_jwt(self, value, metadata, algorithms):
        """Decode a JWT signed with a key of the provider JWK set."""
        registry = JWSRegistry(algorithms=algorithms, strict_check_header=False)
        key_set = KeySet.import_key_set(await self.fetch_jwk_set())
        try:
            return jwt.decode(value, key=key_set, registry=registry)
        except InvalidKeyIdError:
            if metadata.get("jwks_uri") and not _may_refresh_jwk_set(self):
                raise

        key_set = KeySet.import_key_set(await self.fetch_jwk_set(force=True))
        return jwt.decode(value, key=key_set, registry=registry)

    async def userinfo(self, **kwargs):
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
        metadata = await self.load_server_metadata()
        token = kwargs.pop("token", None)
        if token is None:
            token = await _get_requested_token(self, kwargs.get("request"))

        resp = await self.get(metadata["userinfo_endpoint"], token=token, **kwargs)
        resp.raise_for_status()
        if _is_jwt_response(resp):
            decoded = await self._decode_jwt(
                resp.text, metadata, _get_userinfo_algorithms(metadata)
            )
            userinfo = _validate_signed_userinfo(decoded, metadata, self.client_id)
        else:
            userinfo = _parse_json_userinfo(resp, metadata)

        _check_userinfo_sub(userinfo, token)
        return userinfo

    async def parse_id_token(
        self, token, nonce, claims_options=None, claims_cls=None, leeway=120
    ):
        """Return an instance of UserInfo from token's ``id_token``."""
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

        metadata = await self.load_server_metadata()
        claims_options = _get_claims_options(claims_options, metadata)
        alg_values = _get_id_token_algorithms(metadata)

        token = await self._decode_jwt(token["id_token"], metadata, alg_values)
        claims = claims_cls(token.claims, token.header, claims_options, claims_params)
        claims.validate(leeway=leeway)
        return UserInfo(claims)

    async def create_logout_url(
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
        metadata = await self.load_server_metadata()
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
