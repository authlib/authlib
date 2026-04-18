.. _specs/oidc:

OpenID Connect 1.0
==================

.. meta::
    :description: General implementation of OpenID Connect 1.0 in Python.
        Learn how to create a OpenID Connect provider in Python.

This part of the documentation covers the specification of OpenID Connect. Learn
how to use it in :ref:`flask_oidc_server` and :ref:`django_oidc_server`.

OpenID Grants
-------------

.. module:: authlib.oidc.core.grants

.. autoclass:: OpenIDToken
    :show-inheritance:
    :members:

.. autoclass:: OpenIDCode
    :show-inheritance:
    :members:

.. autoclass:: OpenIDImplicitGrant
    :show-inheritance:
    :members:

.. autoclass:: OpenIDHybridGrant
    :show-inheritance:
    :members:

OpenID Endpoints
----------------

.. module:: authlib.oidc.core

.. autoclass:: UserInfoEndpoint
    :show-inheritance:
    :members:

OpenID Claims
-------------

.. module:: authlib.oidc.core.claims

.. autoclass:: IDToken
    :show-inheritance:
    :members:


.. autoclass:: CodeIDToken
    :show-inheritance:
    :members:


.. autoclass:: ImplicitIDToken
    :show-inheritance:
    :members:


.. autoclass:: HybridIDToken
    :show-inheritance:
    :members:

.. autoclass:: UserInfo
    :members:

Dynamic client registration
---------------------------

The `OpenID Connect Dynamic Client Registration <https://openid.net/specs/openid-connect-registration-1_0.html>`__ implementation is based on :ref:`RFC7591: OAuth 2.0 Dynamic Client Registration Protocol <specs/rfc7591>`. To handle OIDC client registration, you can extend your RFC7591 registration endpoint with OIDC claims::

    from authlib.oauth2.rfc7591 import ClientMetadataClaims as OAuth2ClientMetadataClaims
    from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
    from authlib.oidc.registration import ClientMetadataClaims as OIDCClientMetadataClaims

    class MyClientRegistrationEndpoint(ClientRegistrationEndpoint):
        ...

        def get_server_metadata(self):
            ...

    authorization_server.register_endpoint(
        MyClientRegistrationEndpoint(
            claims_classes=[OAuth2ClientMetadataClaims, OIDCClientMetadataClaims]
        )
    )



.. automodule:: authlib.oidc.registration
    :show-inheritance:
    :members:

