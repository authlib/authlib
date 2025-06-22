.. meta::
    :description: Understand the concepts in OAuth 2.0, the authorization flow,
        grant types, roles, authentication methods and etc.
    :image: https://user-images.githubusercontent.com/290496/48670041-e5803e00-eb53-11e8-91a9-3776276d6bf6.png

.. _intro_oauth2:

Introduce OAuth 2.0
===================

    The OAuth 2.0 authorization framework enables a third-party application to
    obtain limited access to an HTTP service, either on behalf of a resource owner
    by orchestrating an approval interaction between the resource owner and the
    HTTP service, or by allowing the third-party application to obtain access on
    its own behalf.

This section will help developers understand the concepts in OAuth 2.0, but not
in deep of OAuth 2.0. Here is an overview of a very simple OAuth 2.0 flow:

.. figure:: https://user-images.githubusercontent.com/290496/48670041-e5803e00-eb53-11e8-91a9-3776276d6bf6.png
    :alt: OAuth 2.0 Flow


OAuth 2.0 Roles
---------------

There are usually four roles in an OAuth 2.0 flow. Let's take GitHub as an example,
you are building an application to analyze one's code on GitHub:

- **Client**: a client is a third-party application, in this case,
  it is your application.

- **Resource Owner**: the users and orgs on GitHub are the resource owners, since
  they own their source code (resources).

- **Resource Server**: The API servers of GitHub. Your **client** will make requests
  to the resource server to fetch source code. The server serves resources.

- **Authorization Server**: The server for **client** to obtain an access token.

OAuth 2.0 Flow
--------------

The above image is a simplified version of an OAuth 2.0 authorization. Let's take
GitHub as an example. A user wants to use your application to analyze his/her
source code on GitHub.

It usually takes these steps:

1. Your application (**client**) prompts the user to log in.
2. The user clicks the *login* button, your application will redirect to GitHub's
   authorize page (**Authorization Server**).
3. The user (he/she is a GitHub user, which means he/she is a **Resource Owner**)
   clicks the *allow* button to tell GitHub that he/she granted the access.
4. The **Authorization Server** issues an **access token** to your application.
   (This step can contain several sub-steps)
5. Your application uses the **access token** to fetch source code from GitHub's
   **Resource Server**, analyze the source code and return the result to your
   application user.

But there are more details inside the flow. The most important thing in OAuth 2.0
is the authorization. A client obtains an access token from the authorization
server with the grant of the resource owner.

Grant Types
-----------

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

Authorization server MAY supports several **grant types** during the **authorization**,
step 1 and 2. A grant type defines a way of how the authorization server will verify
the request and issue the token.

There are lots of built-in grant types in Authlib, including:

- :class:`AuthorizationCodeGrant`
- :class:`ImplicitGrant`
- :class:`ResourceOwnerPasswordCredentialsGrant`
- :class:`ClientCredentialsGrant`
- :class:`RefreshTokenGrant`
- :class:`JWTBearerGrant`

Take ``authorization_code`` as an example, in step 2, when the resource owner granted
the access, **Authorization Server** will return a ``code`` to the client. The client
can use this ``code`` to exchange an access token:

.. code-block:: http
    :emphasize-lines: 3,6

    POST /token HTTP/1.1
    Host: server.example.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA

.. _client_auth_methods:

Client Authentication Methods
-----------------------------

In the above code, there is an ``Authorization`` header; it contains the
information of the client. A client MUST provide its client information to obtain
an access token. There are several ways to provide this data, for instance:

- ``none``: The client is a public client which means it has no client_secret

  .. code-block:: http
    :emphasize-lines: 6

    POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
    &client_id=s6BhdRkqt3

- ``client_secret_post``: The client uses the HTTP POST parameters

  .. code-block:: http
    :emphasize-lines: 6

    POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
    &client_id=s6BhdRkqt3&client_secret=gX1fBat3bV

- ``client_secret_basic``: The client uses HTTP Basic Authorization

  .. code-block:: http
    :emphasize-lines: 3

    POST /token HTTP/1.1
    Host: server.example.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA

There are more client authentication methods defined by OAuth 2.0 extensions,
including ``client_secret_jwt``, ``private_key_jwt``. They can be found in
section :ref:`jwt_client_authentication`.

Token Scopes
------------

Scope is a very important concept in OAuth 2.0. An access token is usually issued
with limited scopes.

For instance, your "source code analyzer" application MAY only have access to the
public repositories of a GitHub user.

Endpoints
---------

The above example only shows one endpoint, which is **token endpoint**. There are
more endpoints in OAuth 2.0. For example:

- :ref:`Token Revocation Endpoint <specs/rfc7009>`
- :ref:`Dynamic Client Registration Endpoint <specs/rfc7591>`
- :ref:`Token Introspection Endpoint <specs/rfc7662>`
