"""
authlib.oauth2.rfc6749.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Base class for OAuth2 endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Any

if TYPE_CHECKING:
    from .requests import OAuth2Request
    from .responses import OAuth2Response


@dataclass
class EndpointRequest:
    """Base class for validated endpoint requests.

    This object is returned by :meth:`Endpoint.validate_request` and contains
    all validated information from the endpoint request. Subclasses add
    endpoint-specific fields.
    """

    request: OAuth2Request
    client: Any = None


class Endpoint:
    """Base class for OAuth2 endpoints.

    Supports two modes of operation:

    **Automatic mode** (non-interactive endpoints):
        Call ``server.create_endpoint_response(name)`` which validates the request
        and creates the response in one step.

    **Interactive mode** (endpoints requiring user confirmation):
        1. Call ``server.validate_endpoint_request(name)`` to get a validated request
        2. Handle user interaction (e.g., show confirmation page)
        3. Call ``server.create_endpoint_response(name, validated_request)`` to complete

    Subclasses must implement :meth:`validate_request` and :meth:`create_response`.
    """

    #: Endpoint name used for registration
    ENDPOINT_NAME: str | None = None

    def __init__(self, server=None):
        self.server = server

    def create_endpoint_request(self, request):
        """Convert framework request to OAuth2Request."""
        return self.server.create_oauth2_request(request)

    def validate_request(self, request: OAuth2Request) -> EndpointRequest:
        """Validate the request and return a validated request object.

        :param request: The OAuth2Request to validate
        :returns: EndpointRequest with validated data
        :raises OAuth2Error: If validation fails
        """
        raise NotImplementedError()

    def create_response(
        self, validated_request: EndpointRequest
    ) -> OAuth2Response | None:
        """Create the HTTP response from a validated request.

        :param validated_request: The validated EndpointRequest
        :returns: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`, or None if
            the application should provide its own response
        """
        raise NotImplementedError()

    def create_endpoint_response(self, request: OAuth2Request) -> OAuth2Response | None:
        """Validate and respond in one step (non-interactive mode).

        :param request: The OAuth2Request to process
        :returns: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`, or None
        """
        validated = self.validate_request(request)
        return self.create_response(validated)

    def __call__(self, request: OAuth2Request) -> OAuth2Response | None:
        return self.create_endpoint_response(request)
