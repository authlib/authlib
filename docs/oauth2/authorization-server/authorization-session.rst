.. _authorization_session:

Authorization Session
=====================

.. meta::
    :description: How Authlib applies prompt, max_age and consent with an
        authorization session.

A client can ask for a recent login with ``prompt=login``, with ``max_age``,
or with the ``default_max_age`` client metadata. It can ask for a new consent
with ``prompt=consent``, or for an account selection with
``prompt=select_account``. Authlib applies these rules. The application gives
facts about the session of the user with an
:class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`, or its OpenID
Connect version :class:`~authlib.oidc.core.AuthorizationSessionMixin`, which
adds the account selection.

:class:`~authlib.oauth2.AuthorizationSession` keeps the start time of the
requests in the session of the web framework. The
:ref:`Flask <flask_odic_max_age>` and :ref:`Django <django_oidc_max_age>`
guides show how to use it.

Interactions
------------

When the user must do something before the authorization response, it is in
``grant.interactions``, in this order: ``"create"``, ``"login"``,
``"select_account"`` and ``"consent"``. ``grant.prompt`` is the first of them.
With ``prompt=none``, the server returns an error instead, such as
``login_required`` or ``consent_required``.

- ``"login"`` is added when the user is not logged in, when the request asks
  for a new login, or when the last login is older than ``max_age``.
- ``"select_account"`` is added when the request asks for it, or when
  ``is_account_selection_needed`` returns true. A login also counts as an
  account selection, so an anonymous user only has to log in.
- ``"consent"`` is added when the request asks for it, or when
  ``is_consent_needed`` returns true. It reads the consents you store: there
  is none, it was revoked, or it does not cover the requested scope.
- ``"create"`` comes from :ref:`specs/prompt_create`.

The time of the login comes from ``get_interaction_time(request, "login")``.
It must come from a real authentication, with a password or another factor.
Do not update it when the user switches to another account or resumes a
session. It becomes the ``auth_time`` claim of the ID token.

Request Start Time
------------------

An interaction that the client asks for is done when it happened after the
authorization request started. A login after this time satisfies
``prompt=login`` and ``max_age=0``. A consent after this time satisfies
``prompt=consent``. ``max_age`` is also measured from this time.

``request.authorization_key`` identifies the authorization request. It is a
hash of the request parameters. It is the same before and after the login,
and when the user submits the consent form. Two requests with the same
parameters have the same key. Clients that send a unique ``state``, ``nonce``
or ``code_challenge`` avoid this.

``request.request_time`` reads the start time from the session on first use.
Authlib reads it when the user must go through an interaction, and when a
rule needs it, for instance with ``prompt=login`` or ``max_age``. With the
OpenID Connect ``prompt=none``, the request is done in one HTTP request: the
start time is unknown, and the session is not written.

Authlib calls ``end_request`` when the request ends: when the user accepts or
denies it, and when ``get_consent_grant`` raises an error. Otherwise, the
same request sent again later would reuse the old time, and the user would
not have to log in.

:class:`~authlib.oauth2.AuthorizationSession` keeps the times for 10 minutes,
and at most 5 of them. Change ``request_time_lifetime`` and
``max_request_times`` to adjust it. A longer time lets the user take more time
to log in. A shorter time limits how long the same request can be sent again
without a new login.

Pitfalls
--------

- If your login view clears or replaces the session, copy
  ``authlib_request_times`` into the new session. Otherwise, the user must
  log in twice. Django's ``login`` keeps the session data, unless another
  user was logged in.
- A cross-site ``POST`` to the authorization endpoint comes without the
  session cookie when it is ``SameSite=Lax``. Redirect such requests to a
  ``GET`` with the same parameters first.
- Two authorization requests in two browser tabs at the same time can
  overwrite each other's start time. The user then has to log in again.
- When the session is a signed cookie, a user can send an old cookie again,
  with an older start time. It is the default in Flask, and the
  ``signed_cookies`` backend in Django. If ``prompt=login`` or ``max_age``
  protect sensitive actions, use a server-side session.
- A response that sends a session cookie built before a login, in another
  tab, overwrites this login. Authlib does not write the session with
  ``prompt=none``, for the silent renewals in an iframe. But Flask sends the
  cookie on every response for a permanent session, with
  ``SESSION_REFRESH_EACH_REQUEST``. A server-side session avoids it.
- To keep the times somewhere else, implement ``get_request_time`` and
  ``end_request`` yourself. Keep the times on the server side. Never read
  them from a request parameter or a form field: a user could send an old
  time and skip the login.

Without a Session
-----------------

Without an authorization session, the OpenID Connect grants ignore
``max_age``, except ``max_age=0``, and the ``auth_time`` claim is the current
time. This is deprecated.

The :ref:`specs/rfc9470` extension applies ``max_age`` to the requests without
the ``openid`` scope too.

API Reference
-------------

.. autoclass:: authlib.oauth2.AuthorizationSession
    :member-order: bysource
    :members:
