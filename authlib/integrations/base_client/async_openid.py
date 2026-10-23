from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import SignedUserInfo
from authlib.oidc.core import UserInfo

__all__ = ["AsyncOpenIDMixin"]


class AsyncOpenIDMixin:
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

    async def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``.

        When the provider returns the UserInfo Claims as a signed JWT
        (``Content-Type: application/jwt``, as allowed by `Section 5.3.2`_),
        the JWT is decoded with the provider's JWK Set, the same trust
        path as :meth:`parse_id_token`, and its ``sub``, ``iss`` and
        ``aud`` claims are validated per `Section 5.3.2`_.

        .. _`Section 5.3.2`: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        """
        metadata = await self.load_server_metadata()
        resp = await self.get(metadata["userinfo_endpoint"], **kwargs)
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type == "application/jwt":
            data = await self._parse_signed_userinfo(resp.text, metadata)
        else:
            data = resp.json()
        return UserInfo(data)

    async def _parse_signed_userinfo(self, text, metadata, leeway=120):
        alg_values = metadata.get("userinfo_signing_alg_values_supported")
        jwks = await self.fetch_jwk_set()
        key_set = KeySet.import_key_set(jwks)
        try:
            token = jwt.decode(
                text,
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )
        except InvalidKeyIdError:
            jwks = await self.fetch_jwk_set(force=True)
            key_set = KeySet.import_key_set(jwks)
            token = jwt.decode(
                text,
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )

        claims = SignedUserInfo(token.claims, token.header)
        # Section 5.3.2: the sub Claim MUST always be returned in the
        # UserInfo Response, and a signed response MUST contain the
        # iss and aud Claims as members.
        claims_options = {
            "sub": {"essential": True},
            "iss": {"essential": True},
            "aud": {"essential": True},
        }
        if "issuer" in metadata:
            claims_options["iss"]["values"] = [metadata["issuer"]]
        if self.client_id:
            claims_options["aud"]["values"] = [self.client_id]
        claims.options = claims_options
        claims.validate(leeway=leeway)
        return claims

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
        if claims_options is None and "issuer" in metadata:
            claims_options = {"iss": {"values": [metadata["issuer"]]}}

        alg_values = metadata.get("id_token_signing_alg_values_supported")
        if not alg_values:
            alg_values = ["RS256"]

        jwks = await self.fetch_jwk_set()
        key_set = KeySet.import_key_set(jwks)
        try:
            token = jwt.decode(
                token["id_token"],
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )
        except InvalidKeyIdError:
            jwks = await self.fetch_jwk_set(force=True)
            key_set = KeySet.import_key_set(jwks)
            token = jwt.decode(
                token["id_token"],
                key=key_set,
                registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
            )

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
