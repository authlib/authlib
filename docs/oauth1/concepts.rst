.. meta::
    :description: Understand the concepts in OAuth 1.0, the authorization flow,
        roles, signatures, and etc.
    :image: https://user-images.githubusercontent.com/290496/48671968-2c316080-eb73-11e8-9e6a-9e895cd67262.png

.. _intro_oauth1:

Concepts
========

OAuth 1.0 is the standardization and combined wisdom of many well established industry protocols
at its creation time. It was first introduced as Twitter's open protocol. It is similar to other protocols
at that time in use (Google AuthSub, AOL OpenAuth, Yahoo BBAuth, Upcoming API, Flickr API, etc).

Authlib implemented OAuth 1.0 according to RFC5849_, this section will help developers understand the
concepts in OAuth 1.0, the authorization flow of OAuth 1.0, and etc.

    OAuth provides a method for clients to access server resources on
    behalf of a resource owner (such as a different client or an end-
    user).  It also provides a process for end-users to authorize third-
    party access to their server resources without sharing their
    credentials (typically, a username and password pair), using user-
    agent redirection.

.. _RFC5849: https://tools.ietf.org/html/rfc5849

Here is an overview of a typical OAuth 1.0 authorization flow:

.. figure:: https://user-images.githubusercontent.com/290496/48671968-2c316080-eb73-11e8-9e6a-9e895cd67262.png
    :alt: OAuth 1.0 Flow

OAuth 1.0 Flow
--------------

Let's take your mobile Twitter app as an example. When a user wants to send a tweet
through your application, he/she needs to authenticate at first. When the app is
opened, and the login button is clicked:

1. **Client** uses its **client credentials** to make a request to server, asking
   the server for a temporary credential.
2. **Server** responds with a **temporary credential** if it verified your client
   credential.
3. **Client** saves temporary credential for later use, then open a web view (browser)
   for **resource owner** to grant the access.
4. When access is granted, **Server** responds with a **verifier** to client.
5. **Client** uses this **verifier and temporary credential** to make a request to
   the server asking for **token credentials**.
6. **Server** responds with access token if it verified everything.

And then **Client** can send tweets with the **token credentials**.

Roles in OAuth 1.0
------------------

To understand above flow, you need to know the roles in OAuth 1.0. There are usually
three roles in an OAuth 1.0 flow. Take the above example, imagining that you are
building a mobile app to send tweets:

- **Client**: a client is a third-party application. In this case, it is your
  Twitter application.
- **Resource Owner**: the users on Twitter are the resource owners, since
  they own their tweets (resources).
- **Server**: authorization and resource server. In this case, it is Twitter.

OAuth 1.0 in HTTP
-----------------

Let's explain OAuth 1.0 in HTTP one more time. The first step is:

**Client** uses its **client credentials** to make a request to server, asking
the server for a temporary credential.

It means we need to ask a temporary credential from Twitter. A temporary credential
is called **request token** in Twitter. The first request is (line breaks are for
display purposes only):

.. code-block:: http

    POST /oauth/request_token HTTP/1.1
    Host: api.twitter.com
    Authorization: OAuth
        oauth_consumer_key="dpf43f3p2l4k3l03",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131200",
        oauth_nonce="wIjqoS",
        oauth_callback="https%3A%2F%.example.com%2Fauth",
        oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D",
        oauth_version="1.0"

And Twitter will response with a temporary credential like:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: application/x-www-form-urlencoded

    oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik
    &oauth_token_secret=Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM
    &oauth_callback_confirmed=true

Our Twitter client will then redirect user to the authorization page::

    https://api.twitter.com/oauth/authenticate?oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik

On this authorization page, if user granted access to your Twitter client, it will
redirect back to your application page, e.g.::

    https://example.com/auth?oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik&oauth_verifier=hfdp7dh39dks9884

And the final step is here, use the temporary credential to exchange access token:

.. code-block:: http

    POST /oauth/access_token HTTP/1.1
    Host: api.twitter.com
    Authorization: OAuth
        oauth_consumer_key="dpf43f3p2l4k3l03",
        oauth_token="Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131201",
        oauth_nonce="walatlh",
        oauth_verifier="hfdp7dh39dks9884",
        oauth_signature=".....",
        oauth_version="1.0"

If everything works well, Twitter would response with the final access token now:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: application/x-www-form-urlencoded

    oauth_token=6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY
    &oauth_token_secret=2EEfA6BG5ly3sR3XjE0IBSnlQu4ZrUzPiYTmrkVU
    &user_id=6253282

You can use the ``oauth_token`` and ``oauth_token_secret`` for later use.
