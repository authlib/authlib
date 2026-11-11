.. _specs/unmet_authentication_requirements:

OpenID Connect Core Error Code unmet_authentication_requirements
=================================================================

.. meta::
    :description: Python API references on the OpenID Connect
        unmet_authentication_requirements error code with Authlib.

.. module:: authlib.oidc.unmet_authentication_requirements

This section contains the implementation of `OpenID Connect Core Error Code
unmet_authentication_requirements`_. The authorization server returns this
error when it cannot authenticate the user as the client requires, for
instance with the ``acr_values`` parameter.

.. _OpenID Connect Core Error Code unmet_authentication_requirements: https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html

Per this specification, the server SHALL return this error when the ``claims``
parameter requests an essential ``acr`` that it cannot meet. Register
:class:`UnmetAuthenticationRequirements` on the authorization server to return
it in this case:

.. code-block:: python

    from authlib.oidc.unmet_authentication_requirements import (
        UnmetAuthenticationRequirements,
    )

    authorization_server.register_extension(UnmetAuthenticationRequirements())

Without this extension, Authlib refuses this request with ``access_denied``.
To refuse other requests, such as an ``acr_values`` that the authentication
does not satisfy, raise :class:`UnmetAuthenticationRequirementsError` from
``get_acr`` of the authorization session, see :ref:`authorization_session`.
The error is redirected to the client.

API Reference
-------------

.. autoclass:: UnmetAuthenticationRequirements
    :members:

.. autoclass:: UnmetAuthenticationRequirementsError
