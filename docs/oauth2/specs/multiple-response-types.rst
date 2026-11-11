.. _specs/multiple_response_types:

OAuth 2.0 Multiple Response Type Encoding Practices
===================================================

.. meta::
    :description: Python API references on OAuth 2.0 Multiple Response Type
        Encoding Practices with Authlib implementation.

.. module:: authlib.oauth2.multiple_response_types

This section contains the generic implementation of `OAuth 2.0 Multiple
Response Type Encoding Practices`_ (MRT). With the ``response_mode`` parameter, a
client chooses how it receives the authorization response: in the query or
in the fragment of its redirect URI.

.. _OAuth 2.0 Multiple Response Type Encoding Practices: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html

Authorization Endpoint
----------------------

Register the :class:`MultipleResponseTypes` extension on your authorization
server:

.. code-block:: python

    from authlib.oauth2.multiple_response_types import MultipleResponseTypes

    authorization_server.register_extension(MultipleResponseTypes())

It applies to all the authorization grants. Errors use the requested response
mode too. The server refuses a response mode with an ``invalid_request``
error, sent with the default response mode of the response type, when:

- the mode is not in the ``response_modes_supported`` metadata;
- the mode is ``query`` and the response contains an access token or an ID
  Token (MRT §7).

Without this extension, Authlib ignores the ``response_mode`` parameter. The
OpenID Connect implicit and hybrid grants still accept it, but this is
deprecated.

Response modes
--------------

The server accepts the modes of its ``response_modes_supported`` metadata.
Return them from :meth:`MultipleResponseTypes.get_server_metadata`. The
default is ``query`` and ``fragment``, per :rfc:`RFC 8414 §2 <8414#section-2>`:

.. code-block:: python

    class MyMultipleResponseTypes(MultipleResponseTypes):
        def get_server_metadata(self):
            return {"response_modes_supported": ["query", "fragment"]}

Other specifications define more response modes, such as :ref:`form_post
<specs/form_post>`. Pass them to the extension as :class:`ResponseMode`
instances:

.. code-block:: python

    from authlib.oauth2.form_post import FormPost

    authorization_server.register_extension(MyMultipleResponseTypes([FormPost()]))

The ``none`` response type
--------------------------

With ``response_type=none``, the user grants or denies the request, and the
client receives no code and no token. Per MRT §4, the response contains
``state``, and its default response mode is the query response mode.
Register :class:`NoneResponseTypeGrant` to support it:

.. code-block:: python

    from authlib.oauth2.multiple_response_types import NoneResponseTypeGrant

    authorization_server.register_grant(NoneResponseTypeGrant)

The client must be allowed to use the ``none`` response type. Add ``none``
to the ``response_types_supported`` metadata of the server, so that clients
can register for it. The grant stores nothing: record the consent of the
user in your application if you need it.

API Reference
-------------

.. autoclass:: MultipleResponseTypes
    :member-order: bysource
    :members:

.. autoclass:: ResponseMode
    :member-order: bysource
    :members:

.. autoclass:: NoneResponseTypeGrant
    :member-order: bysource
    :members:
