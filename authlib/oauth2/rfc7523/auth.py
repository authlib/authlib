from joserfc.jwk import OctKey
from joserfc.jwk import import_key
from joserfc.jws import JWSRegistry

from authlib.common.urls import add_params_to_qs

from .assertion import client_secret_jwt_sign
from .assertion import private_key_jwt_sign
from .client import ASSERTION_TYPE


class ClientSecretJWT:
    """Authentication method for OAuth 2.0 Client. This authentication
    method is called ``client_secret_jwt``, which is using ``client_id``
    and ``client_secret`` constructed with JWT to identify a client.

    Here is an example of use ``client_secret_jwt`` with Requests Session::

        from authlib.integrations.requests_client import OAuth2Session

        token_endpoint = "https://example.com/oauth/token"
        session = OAuth2Session(
            "your-client-id",
            "your-client-secret",
            token_endpoint_auth_method="client_secret_jwt",
        )
        session.register_client_auth_method(ClientSecretJWT(token_endpoint))
        session.fetch_token(token_endpoint)

    :param token_endpoint: A string URL of the token endpoint
    :param claims: Extra JWT claims
    :param headers: Extra JWT headers
    :param alg: ``alg`` value, default is HS256
    :param expires_in: Lifetime of the client assertion in seconds,
        default is 3600. Identity providers may cap this, e.g. Auth0
        rejects assertions that live longer than 5 minutes.
    """

    name = "client_secret_jwt"
    alg = "HS256"
    expires_in = 3600

    def __init__(
        self, token_endpoint=None, claims=None, headers=None, alg=None, expires_in=None
    ):
        self.token_endpoint = token_endpoint
        self.claims = claims
        self.headers = headers
        if alg is not None:
            self.alg = alg
        if expires_in is not None:
            self.expires_in = expires_in

    def sign(self, auth, token_endpoint):
        if isinstance(auth.client_secret, OctKey):
            key = auth.client_secret
        else:
            key = OctKey.import_key(auth.client_secret)
        return client_secret_jwt_sign(
            key,
            client_id=auth.client_id,
            token_endpoint=token_endpoint,
            claims=self.claims,
            header=self.headers,
            alg=self.alg,
            expires_in=self.expires_in,
        )

    def __call__(self, auth, method, uri, headers, body):
        token_endpoint = self.token_endpoint
        if not token_endpoint:
            token_endpoint = uri

        client_assertion = self.sign(auth, token_endpoint)
        body = add_params_to_qs(
            body or "",
            [
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", client_assertion),
            ],
        )
        return uri, headers, body


class PrivateKeyJWT(ClientSecretJWT):
    """Authentication method for OAuth 2.0 Client. This authentication
    method is called ``private_key_jwt``, which is using ``client_id``
    and ``private_key`` constructed with JWT to identify a client.

    Here is an example of use ``private_key_jwt`` with Requests Session::

        from authlib.integrations.requests_client import OAuth2Session

        token_endpoint = "https://example.com/oauth/token"
        session = OAuth2Session(
            "your-client-id",
            "your-client-private-key",
            token_endpoint_auth_method="private_key_jwt",
        )
        session.register_client_auth_method(PrivateKeyJWT(token_endpoint))
        session.fetch_token(token_endpoint)

    :param token_endpoint: A string URL of the token endpoint
    :param claims: Extra JWT claims
    :param headers: Extra JWT headers. The ``kid`` of the key is added when
        the key has one and the headers do not set it.
    :param alg: ``alg`` value, default is RS256
    :param expires_in: Lifetime of the client assertion in seconds,
        default is 3600. Identity providers may cap this, e.g. Auth0
        rejects assertions that live longer than 5 minutes.

    The private key can be an RSA, EC or OKP key: a joserfc key, a PEM string
    or a JWK dict. The type of the key must match ``alg``.
    """

    name = "private_key_jwt"
    alg = "RS256"

    def sign(self, auth, token_endpoint):
        key = auth.client_secret
        if isinstance(key, (str, bytes, dict)):
            algorithm = JWSRegistry.algorithms.get(self.alg)
            key_type = getattr(algorithm, "key_type", None)
            if key_type not in ("EC", "OKP"):
                key_type = "RSA"

            key = import_key(key, key_type)

        return private_key_jwt_sign(
            key,
            client_id=auth.client_id,
            token_endpoint=token_endpoint,
            claims=self.claims,
            header=self.headers,
            alg=self.alg,
            expires_in=self.expires_in,
        )
