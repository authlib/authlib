Reference
=========

This part of the documentation covers the interface of Flask OAuth 1.0
Server.

.. module:: authlib.integrations.flask_oauth1

.. autoclass:: AuthorizationServer
    :members:

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. data:: current_credential

    Routes protected by :class:`ResourceProtector` can access current credential
    with this variable.
