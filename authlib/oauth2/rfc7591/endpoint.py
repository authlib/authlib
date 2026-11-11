import binascii
import os
import time

from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import audience_matches
from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token

from ..rfc6749 import InvalidRequestError
from ..rfc6749 import JsonResponse
from ..rfc6749 import MissingAuthorizationError
from ..rfc6750 import InvalidTokenError
from .claims import ClientMetadataClaims
from .errors import InvalidClientMetadataError
from .errors import InvalidSoftwareStatementError
from .errors import UnapprovedSoftwareStatementError


class ClientRegistrationEndpoint:
    """The client registration endpoint is an OAuth 2.0 endpoint designed to
    allow a client to be registered with the authorization server.
    """

    ENDPOINT_NAME = "client_registration"

    #: Rewrite this value with a list to support ``software_statement``
    #: e.g. ``software_statement_alg_values_supported = ['RS256']``
    software_statement_alg_values_supported = None

    #: Seconds of clock skew allowed when checking the ``exp``, ``nbf`` and
    #: ``iat`` claims of a software statement.
    software_statement_leeway = 60

    def __init__(self, server=None, claims_classes=None):
        self.server = server
        self.claims_classes = claims_classes or [ClientMetadataClaims]

    def __call__(self, request):
        return self.create_registration_response(request)

    def create_registration_response(self, request):
        token = self.authenticate_token(request)
        if not token:
            # Per RFC 6750 §3.1, a request without authentication information
            # gets no error code.
            if not request.headers.get("Authorization"):
                raise MissingAuthorizationError()
            raise InvalidTokenError()

        request.credential = token

        client_metadata = self.extract_client_metadata(request)
        client_info = self.generate_client_info(request)
        body = {}
        body.update(client_metadata)
        body.update(client_info)
        client = self.save_client(client_info, client_metadata, request)
        registration_info = self.generate_client_registration_info(client, request)
        if registration_info:
            body.update(registration_info)
        return JsonResponse(body, status_code=201)

    def extract_client_metadata(self, request):
        json_data = _get_json_object(request).copy()
        if not json_data:
            raise InvalidRequestError()

        software_statement = json_data.pop("software_statement", None)
        if software_statement and self.software_statement_alg_values_supported:
            data = self.extract_software_statement(software_statement, request)
            json_data.update(data)

        client_metadata = {}
        server_metadata = self.get_server_metadata()
        for claims_class in self.claims_classes:
            options = (
                claims_class.get_claims_options(server_metadata)
                if hasattr(claims_class, "get_claims_options") and server_metadata
                else {}
            )
            claims = claims_class(json_data, {}, options, server_metadata)
            try:
                claims.validate()
            except JoseError as error:
                raise InvalidClientMetadataError(error.description) from error

            client_metadata.update(**claims.get_registered_claims())
        return client_metadata

    def extract_software_statement(self, software_statement, request):
        key = self.resolve_public_key(request)
        if not key:
            raise UnapprovedSoftwareStatementError()

        try:
            key = import_any_key(key)
            algorithms = self.software_statement_alg_values_supported
            token = jwt.decode(software_statement, key, algorithms=algorithms)

            # Per RFC 7519 §4.1.4 and §4.1.5, a JWT must not be accepted after
            # its exp or before its nbf.
            registry = jwt.JWTClaimsRegistry(leeway=self.software_statement_leeway)
            registry.validate(token.claims)
        except JoseError as exc:
            raise InvalidSoftwareStatementError() from exc

        # Per RFC 7519 §4.1.3, if the principal processing the claim does not
        # identify itself with a value in the "aud" claim when this claim is
        # present, then the JWT MUST be rejected.
        if "aud" in token.claims and not audience_matches(
            token.claims["aud"], self.get_audiences()
        ):
            raise InvalidSoftwareStatementError(
                "The 'aud' claim does not identify this server."
            )

        return token.claims

    def generate_client_info(self, request):
        # https://tools.ietf.org/html/rfc7591#section-3.2.1
        client_id = self.generate_client_id(request)
        client_secret = self.generate_client_secret(request)
        client_id_issued_at = int(time.time())
        client_secret_expires_at = 0
        return dict(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=client_id_issued_at,
            client_secret_expires_at=client_secret_expires_at,
        )

    def generate_client_registration_info(self, client, request):
        """Generate ```registration_client_uri`` and ``registration_access_token``
        for RFC7592. This method returns ``None`` by default. Developers MAY rewrite
        this method to return registration information.
        """
        return None

    def create_endpoint_request(self, request):
        return self.server.create_json_request(request)

    def generate_client_id(self, request):
        """Generate ``client_id`` value. Developers MAY rewrite this method
        to use their own way to generate ``client_id``.
        """
        return generate_token(42)

    def generate_client_secret(self, request):
        """Generate ``client_secret`` value. Developers MAY rewrite this method
        to use their own way to generate ``client_secret``.
        """
        return binascii.hexlify(os.urandom(24)).decode("ascii")

    def get_server_metadata(self):
        """Return server metadata which includes supported grant types,
        response types and etc.
        """
        raise NotImplementedError()

    def get_audiences(self):
        """Return the accepted values of the software statement ``aud`` claim.

        A software statement with an ``aud`` claim is rejected when ``aud`` does
        not contain one of these values. A software statement without ``aud``
        is accepted. By default, it returns the ``issuer`` of
        :meth:`get_server_metadata`, or an empty list when there is none.
        Developers MAY re-implement it in subclass, for example to also accept
        the registration endpoint URL::

            def get_audiences(self):
                metadata = self.get_server_metadata()
                return [metadata["issuer"], metadata["registration_endpoint"]]

        :return: list of strings
        """
        issuer = (self.get_server_metadata() or {}).get("issuer")
        return [issuer] if issuer else []

    def authenticate_token(self, request):
        """Authenticate current credential who is requesting to register a client.
        Developers MUST implement this method in subclass::

            def authenticate_token(self, request):
                auth = request.headers.get("Authorization")
                return get_token_by_auth(auth)

        Return ``None`` for an unknown, expired or revoked token. The endpoint
        does not check the token state itself. For open registration, return a
        truthy value for requests without token. When it returns ``None``, the
        endpoint responds with HTTP 401, per :rfc:`7591#section-3.2.2` and
        :rfc:`6750#section-3`.

        :return: token instance, or ``None`` if the request is not allowed
        """
        raise NotImplementedError()

    def resolve_public_key(self, request):
        """Resolve a public key for decoding ``software_statement``. If
        ``enable_software_statement=True``, developers MUST implement this
        method in subclass::

            def resolve_public_key(self, request):
                return get_public_key_from_user(request.credential)

        :return: JWK or Key string
        """
        raise NotImplementedError()

    def save_client(self, client_info, client_metadata, request):
        """Save client into database. Developers MUST implement this method
        in subclass::

            def save_client(self, client_info, client_metadata, request):
                client = OAuthClient(
                    client_id=client_info['client_id'],
                    client_secret=client_info['client_secret'],
                    ...
                )
                client.save()
                return client
        """
        raise NotImplementedError()


def _get_json_object(request):
    """Return the request body, which must be a JSON object."""
    data = request.payload.data
    if not isinstance(data, dict):
        raise InvalidRequestError()

    return data
