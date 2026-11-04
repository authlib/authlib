.. _specs/prompt_create:

Initiating User Registration via OpenID Connect 1.0
===================================================

.. meta::
    :description: Python API references on Initiating User Registration via
        OpenID Connect 1.0 with Authlib implementation.

.. module:: authlib.oidc.prompt_create

This section contains the generic implementation of `Initiating User
Registration via OpenID Connect 1.0`_. With ``prompt=create``, a client asks
the OpenID Provider to show the account creation page instead of the login
page.

.. _Initiating User Registration via OpenID Connect 1.0: https://openid.net/specs/openid-connect-prompt-create-1_0.html

Authorization Endpoint
----------------------

Register the :class:`PromptCreate` extension on your authorization server::

    from authlib.oidc.prompt_create import PromptCreate

    authorization_server.register_extension(PromptCreate())

It applies to the OpenID Connect code, implicit and hybrid flows. When the
authorization request of an anonymous user contains ``prompt=create``,
``"create"`` is the first of ``grant.interactions``, before ``"login"``, and
``grant.prompt`` is ``"create"``. Show the account creation page in your
authorization endpoint::

    @app.route("/oauth/authorize")
    def authorize():
        grant = authorization_server.get_consent_grant(end_user=current_user)
        if grant.prompt == "create":
            return render_template("register.html", grant=grant)
        ...

For a logged-in user, ``create`` is ignored. The other interactions, such as
a login required by ``max_age``, still apply. So log the user in at the end of
the account creation, and send them back to the authorization URL. If you
want to show the account creation page to logged-in users too, read the
``prompt`` parameter of the request.

The flow is only successful when the client gets an ID Token (Initiating User
Registration via OpenID Connect 1.0 §4.1).

Without this extension, Authlib ignores the ``create`` value.

Discovery
---------

An OpenID Provider that supports this specification must publish
``prompt_values_supported`` (Initiating User Registration via OpenID Connect
1.0 §4.2). The list must contain ``create`` and all the
other prompt values that the provider supports. Add the discovery class to
your metadata validation::

    from authlib.oidc import discovery
    from authlib.oidc import prompt_create

    metadata = discovery.OpenIDProviderMetadata({
        ...,
        "prompt_values_supported": ["none", "login", "consent", "create"],
    })
    metadata.validate(metadata_classes=[prompt_create.OpenIDProviderMetadata])

API Reference
-------------

.. autoclass:: PromptCreate
    :member-order: bysource
    :members:

.. autoclass:: OpenIDProviderMetadata
    :member-order: bysource
    :members:
