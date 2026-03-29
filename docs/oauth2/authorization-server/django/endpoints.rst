Token Endpoints
===============

Django OAuth 2.0 authorization server has a method to register other token
endpoints: ``authorization_server.register_endpoint``. Available endpoints
for now:

1. Revocation Endpoint from RFC7009
2. Introspection Endpoint from RFC7662

Revocation Endpoint
-------------------

The revocation endpoint for OAuth authorization servers allows clients to
notify the authorization server that a previously obtained refresh or access
token is no longer needed.

This allows the authorization server to clean up security credentials.
A revocation request will invalidate the actual token and, if applicable, other
tokens based on the same authorization grant.

For example, a client may request the revocation of a refresh token
with the following request:

.. code-block:: http

    POST /oauth/revoke HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

    token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

In Authlib Django OAuth 2.0 provider, we can simply add this feature::

    from authlib.integrations.django_oauth2 import RevocationEndpoint
    from django.views.decorators.http import require_http_methods

    # see Authorization Server chapter
    server.register_endpoint(RevocationEndpoint)

    @require_http_methods(["POST"])
    def revoke_token(request):
        return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME, request)

That's all we need. Add this ``revoke_token`` to your routes to enable it. The suggested
url path is ``/oauth/revoke``.

Introspection Endpoint
----------------------

Check :ref:`register_introspection_endpoint` to get more details.
