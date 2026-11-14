import logging
from urllib.parse import urlparse

from ..rfc6749 import BaseGrant
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import InvalidScopeError
from ..rfc6749 import JsonResponse
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749 import TokenMixin
from ..rfc6749 import UnauthorizedClientError
from ..rfc6749 import scope_to_list
from .errors import InvalidTargetError

log = logging.getLogger(__name__)

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
SAML1_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml1"
SAML2_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml2"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """The client exchanges a security token for another one, issued for the
    same subject.

    Implement :meth:`authenticate_subject_token`, :meth:`authenticate_user`
    and :meth:`check_permission` in a subclass, and
    :meth:`authenticate_actor_token` to accept actor tokens. The issued token
    is an access token, unless :meth:`issue_token` is overridden.

    :rfc:`8693`
    """

    GRANT_TYPE = TOKEN_EXCHANGE_GRANT_TYPE

    def validate_token_request(self):
        """The client makes a token exchange request to the token endpoint
        with the following parameters, per :rfc:`8693#section-2.1`:

        grant_type
            REQUIRED.  The value "urn:ietf:params:oauth:grant-type:token-
            exchange" indicates that a token exchange is being performed.

        resource
            OPTIONAL.  A URI that indicates the target service or resource
            where the client intends to use the requested security token.

        audience
            OPTIONAL.  The logical name of the target service where the client
            intends to use the requested security token.

        scope
            OPTIONAL.

        requested_token_type
            OPTIONAL.  An identifier, as described in Section 3, for the type
            of the requested security token.

        subject_token
            REQUIRED.  A security token that represents the identity of the
            party on behalf of whom the request is being made.

        subject_token_type
            REQUIRED.  An identifier, as described in Section 3, that
            indicates the type of the security token in the "subject_token"
            parameter.

        actor_token
            OPTIONAL.  A security token that represents the identity of the
            acting party.

        actor_token_type
            An identifier, as described in Section 3, that indicates the type
            of the security token in the "actor_token" parameter.  This is
            REQUIRED when the "actor_token" parameter is present in the
            request but MUST NOT be included otherwise.

        For example:

        .. code-block:: http

            POST /as/token.oauth2 HTTP/1.1
            Host: as.example.com
            Authorization: Basic cnMwODpsb25nLXNlY3VyZS1yYW5kb20tc2VjcmV0
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
            &resource=https%3A%2F%2Fbackend.example.com%2Fapi
            &subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
            &subject_token_type=
             urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
        """
        client = self.authenticate_token_endpoint_client()
        log.debug("Validate token request of %r", client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )

        form = self.request.form
        subject_token = form.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request")
        subject_token_type = form.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request")

        actor_token = form.get("actor_token")
        actor_token_type = form.get("actor_token_type")
        if actor_token and not actor_token_type:
            raise InvalidRequestError("Missing 'actor_token_type' in request")
        if actor_token_type and not actor_token:
            raise InvalidRequestError(
                "'actor_token_type' must not be included without 'actor_token'"
            )

        # "The value of the "resource" parameter MUST be an absolute URI, as
        # specified by Section 4.3 of [RFC3986], that MAY include a query
        # component and MUST NOT include a fragment component."
        for resource in self._resources:
            if not urlparse(resource).scheme or "#" in resource:
                raise InvalidRequestError(f"Invalid 'resource' value: {resource!r}")

        self.request.client = client
        self.validate_requested_scope()

        # "In processing the request, the authorization server MUST perform the
        # appropriate validation procedures for the indicated token type and,
        # if the actor token is present, also perform the appropriate
        # validation procedures for its indicated token type."
        subject_token = self.authenticate_subject_token(
            subject_token, subject_token_type
        )
        if not subject_token:
            raise InvalidRequestError("Invalid 'subject_token'")
        user = self.authenticate_user(subject_token)
        if not user:
            raise InvalidRequestError("Invalid 'subject_token'")

        if actor_token:
            actor_token = self.authenticate_actor_token(actor_token, actor_token_type)
            if not actor_token:
                raise InvalidRequestError("Invalid 'actor_token'")

        scope = self._resolve_scope(subject_token)

        # "If the request itself is not valid or if either the "subject_token"
        # or "actor_token" are invalid for any reason, or are unacceptable
        # based on policy, the authorization server MUST construct an error
        # response, as specified in Section 5.2 of [RFC6749].  The value of
        # the "error" parameter MUST be the "invalid_request" error code."
        if not self.check_permission(
            client, subject_token, actor_token or None, scope_to_list(scope) or []
        ):
            raise InvalidRequestError(
                "The client is not allowed to exchange 'subject_token'"
            )

        self.request.user = user
        self.request.scope = scope
        self.request.subject_token = subject_token
        self.request.actor_token = actor_token or None

    def create_token_response(self):
        """If the request is valid, the authorization server issues the token,
        per :rfc:`8693#section-2.2.1`:

        .. code-block:: http

            HTTP/1.1 200 OK
            Content-Type: application/json
            Cache-Control: no-cache, no-store

            {
             "access_token":"eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9...",
             "issued_token_type":
                 "urn:ietf:params:oauth:token-type:access_token",
             "token_type":"Bearer",
             "expires_in":60
            }
        """
        token = self.issue_token(
            self.request.subject_token,
            self.request.actor_token,
            self.request.form.get("requested_token_type") or None,
            self._resources,
            [
                audience
                for audience in self.request.payload.datalist.get("audience", [])
                if audience
            ],
        )
        log.debug("Issue token %r to %r", token, self.request.client)
        return JsonResponse(token, headers=self.TOKEN_RESPONSE_HEADER)

    @property
    def _resources(self):
        datalist = self.request.payload.datalist
        return [resource for resource in datalist.get("resource", []) if resource]

    def _resolve_scope(self, subject_token):
        """Return the scope of the issued token. For a subject token that is a
        :class:`~authlib.oauth2.rfc6749.TokenMixin`, the requested scope is
        bounded by its scope, and defaults to it.
        """
        scope = self.request.payload.scope
        if not isinstance(subject_token, TokenMixin):
            return scope

        original_scope = subject_token.get_scope()
        if not scope:
            return original_scope

        if not set(scope_to_list(original_scope) or []).issuperset(
            scope_to_list(scope)
        ):
            raise InvalidScopeError("The requested scope exceeds 'subject_token'")
        return scope

    def issue_token(
        self, subject_token, actor_token, requested_token_type, resource, audience
    ):
        """Issue the token of the response, for ``request.user``, ``request.client``
        and ``request.scope``.

        The default implementation issues an access token without a refresh
        token. It rejects any other ``requested_token_type``, and any
        ``resource`` or ``audience``, with ``invalid_target``: "If the
        authorization server is unwilling or unable to issue a token for any
        target service indicated by the "resource" or "audience" parameters,
        the "invalid_target" error code SHOULD be used in the error response."

        Override it to issue another type of token, or a token for a target.
        The returned dict needs ``access_token``, ``issued_token_type`` and
        ``token_type``, which is ``"N_A"`` when the token is not an access
        token.

        :param subject_token: the token returned by
            :meth:`authenticate_subject_token`
        :param actor_token: the token returned by
            :meth:`authenticate_actor_token`, or *None*
        :param requested_token_type: the ``requested_token_type`` parameter,
            or *None*
        :param resource: the list of ``resource`` parameters
        :param audience: the list of ``audience`` parameters
        :return: the token dict
        """
        if requested_token_type not in (None, ACCESS_TOKEN_TYPE):
            raise InvalidRequestError(
                f"Unsupported 'requested_token_type': {requested_token_type!r}"
            )
        if resource or audience:
            raise InvalidTargetError()

        token = self.generate_token(
            user=self.request.user,
            scope=self.request.scope,
            include_refresh_token=False,
        )
        self.save_token(token)
        token["issued_token_type"] = ACCESS_TOKEN_TYPE
        return token

    def authenticate_subject_token(self, subject_token, subject_token_type):
        """Validate the subject token for its type. Implement it in a
        subclass::

            def authenticate_subject_token(self, subject_token, subject_token_type):
                if subject_token_type != ACCESS_TOKEN_TYPE:
                    return None
                token = Token.query.filter_by(access_token=subject_token).first()
                if token and not token.is_expired() and not token.is_revoked():
                    return token

        When it returns a :class:`~authlib.oauth2.rfc6749.TokenMixin`, the
        requested scope must be within its scope.

        :param subject_token: the ``subject_token`` parameter
        :param subject_token_type: the ``subject_token_type`` parameter
        :return: the validated token, or *None* to reject it
        """
        raise NotImplementedError()

    def authenticate_user(self, subject_token):
        """Return the user the subject token represents. Implement it in a
        subclass::

            def authenticate_user(self, subject_token):
                return subject_token.user

        :param subject_token: the token returned by
            :meth:`authenticate_subject_token`
        :return: the user, or *None* to reject the request
        """
        raise NotImplementedError()

    def authenticate_actor_token(self, actor_token, actor_token_type):
        """Validate the actor token for its type. Implement it in a subclass
        to accept actor tokens. By default, a request with an actor token is
        rejected.

        :param actor_token: the ``actor_token`` parameter
        :param actor_token_type: the ``actor_token_type`` parameter
        :return: the validated token, or *None* to reject it
        """
        return None

    def check_permission(self, client, subject_token, actor_token, scopes):
        """Check if the client may exchange the subject token for the scopes,
        acting as the actor when there is one. Implement it in a subclass::

            def check_permission(self, client, subject_token, actor_token, scopes):
                return subject_token.client_id == client.get_client_id()

        :param client: the authenticated client
        :param subject_token: the token returned by
            :meth:`authenticate_subject_token`
        :param actor_token: the token returned by
            :meth:`authenticate_actor_token`, or *None*
        :param scopes: the scopes of the issued token
        :return: bool
        """
        raise NotImplementedError()
