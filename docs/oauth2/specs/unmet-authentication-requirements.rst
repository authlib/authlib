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

Authlib does not raise it by itself. Raise it from ``get_acr`` of the
authorization session to refuse a request, see :ref:`authorization_session`.
It is redirected to the client.

API Reference
-------------

.. autoclass:: UnmetAuthenticationRequirementsError
