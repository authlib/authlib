.. _specs/form_post:

OAuth 2.0 Form Post Response Mode
=================================

.. meta::
    :description: Python API references on OAuth 2.0 Form Post Response Mode
        with Authlib implementation.

.. module:: authlib.oauth2.form_post

This section contains the generic implementation of `OAuth 2.0 Form Post
Response Mode`_. With ``response_mode=form_post``, the authorization server
answers with an HTML form that the user agent submits to the redirect URI.
The response parameters are sent in the body of a POST request, not in the
URI.

.. _OAuth 2.0 Form Post Response Mode: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html

.. mermaid::

    sequenceDiagram
        autonumber
        participant User as User's browser<br/>(User Agent)
        participant Client
        box rgba(80, 120, 220, 0.12) FormPost
            participant AS as Authorization Server
        end

        Client-->>User: 302 Found → /authorize?response_mode=form_post
        User->>AS: GET /authorize
        Note over User,AS: The user logs in and approves
        AS-->>User: 200 OK + HTML form
        User->>Client: POST redirect_uri (code, state)

1. The client redirects the browser to the authorization endpoint with
   ``response_mode=form_post``.
2. The authorization server validates the request. :class:`FormPost` refuses
   a redirect URI that does not use http or https.
3. The user logs in and approves the request.
4. The server answers with an HTML form that submits itself. The response is
   not cached.
5. The browser posts the response parameters to the redirect URI.

Authorization Endpoint
----------------------

Pass :class:`FormPost` to the :ref:`Multiple Response Types
<specs/multiple_response_types>` extension, and add ``form_post`` to its
``response_modes_supported`` metadata:

.. code-block:: python

    from authlib.oauth2.form_post import FormPost
    from authlib.oauth2.multiple_response_types import MultipleResponseTypes

    class MyMultipleResponseTypes(MultipleResponseTypes):
        def get_server_metadata(self):
            return {"response_modes_supported": ["query", "fragment", "form_post"]}

    authorization_server.register_extension(MyMultipleResponseTypes([FormPost()]))

It applies to all the authorization grants. A grant can also use
``form_post`` by default with ``RESPONSE_MODE = "form_post"``.

The redirect URI must use http or https. Otherwise, the server refuses the
request with an ``invalid_request`` error, without redirection, and renders no
form.

API Reference
-------------

.. autoclass:: FormPost
    :member-order: bysource
    :members:
