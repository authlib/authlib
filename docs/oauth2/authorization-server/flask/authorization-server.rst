Authorization Server
====================

The Authorization Server provides several endpoints for authorization, issuing
tokens, refreshing tokens and revoking tokens. When the resource owner (user)
grants the authorization, this server will issue an access token to the client.

Before creating the authorization server, we need to understand several
concepts:

Resource Owner
--------------

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods.

Implement the ``get_user_id()`` method on the resource owner model. Here is
an example with SQLAlchemy:

.. code-block:: python

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        # other columns

        def get_user_id(self):
            return self.id

Client
------

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**
- Client Token Endpoint Authentication Method

Authlib has provided a mixin for SQLAlchemy, define the client with this mixin:

.. code-block:: python

    from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin

    class Client(db.Model, OAuth2ClientMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

A client is registered by a user (developer) on your website. If you decide to
implement all the missing methods by yourself, get a deep inside with
:class:`~authlib.oauth2.rfc6749.ClientMixin` API reference.

Token
-----

Authlib issues Bearer Tokens (:rfc:`6750`).

Tokens are used to access the users' resources. A token is issued with a
valid duration, limited scopes and etc. It contains at least:

- **access_token**: a token to authorize the http requests.
- **refresh_token**: (optional) a token to exchange a new access token
- **client_id**: this token is issued to which client
- **expires_at**: when will this token expired
- **scope**: a limited scope of resources that this token can access

With the SQLAlchemy mixin provided by Authlib:

.. code-block:: python

    from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin

    class Token(db.Model, OAuth2TokenMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

A token is associated with a resource owner. There is no certain name for
it, here we call it ``user``, but it can be anything else.

If you decide to implement all the missing methods by yourself, get a deep
inside the :class:`~authlib.oauth2.rfc6749.TokenMixin` API reference.

Server
------

Authlib provides a ready to use
:class:`~authlib.integrations.flask_oauth2.AuthorizationServer`
which has built-in tools to handle requests and responses:

.. code-block:: python

    from authlib.integrations.flask_oauth2 import AuthorizationServer

    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    def save_token(token_data, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            # client_credentials grant_type
            user_id = request.client.user_id
            # or, depending on how you treat client_credentials
            user_id = None
        token = Token(
            client_id=request.client.client_id,
            user_id=user_id,
            **token_data
        )
        db.session.add(token)
        db.session.commit()

    # or with the helper
    from authlib.integrations.sqla_oauth2 import (
        create_query_client_func,
        create_save_token_func
    )
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)

    server = AuthorizationServer(
        app, query_client=query_client, save_token=save_token
    )

It can also be initialized lazily with init_app:

.. code-block:: python

    server = AuthorizationServer()
    server.init_app(app, query_client=query_client, save_token=save_token)

It works well without configuration. However, it can be configured with these
settings:

================================== ==================================================
OAUTH2_TOKEN_EXPIRES_IN            A dict to define ``expires_in`` for each grant
OAUTH2_ACCESS_TOKEN_GENERATOR      A function or string of module path for importing
                                   a function to generate ``access_token``
OAUTH2_REFRESH_TOKEN_GENERATOR     A function or string of module path for importing
                                   a function to generate ``refresh_token``. It can
                                   also be ``True/False``
OAUTH2_ERROR_URIS                  A list of tuple for (``error``, ``error_uri``)
================================== ==================================================

.. hint::

    Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``:

    .. code-block:: python

        OAUTH2_TOKEN_EXPIRES_IN = {
            'authorization_code': 864000,
            'implicit': 3600,
            'password': 864000,
            'client_credentials': 864000
        }

    Here is an example of ``OAUTH2_ACCESS_TOKEN_GENERATOR``:

    .. code-block:: python

        def gen_access_token(client, grant_type, user, scope, expires_in, request):
            return create_some_random_string()

    ``expires_in`` is the lifetime of the token, in seconds. A self-contained
    token, such as a signed one, can use it to set its expiration time.
    ``request`` is the current request.
    ``OAUTH2_REFRESH_TOKEN_GENERATOR`` accepts the same parameters, except
    ``expires_in``.

Now define an endpoint for authorization. This endpoint is used by
``authorization_code`` and ``implicit`` grants. ``current_user`` comes from
the login system of your application:

.. skip: next

.. code-block:: python

    from authlib.oauth2 import OAuth2Error
    from flask import redirect, request, render_template, url_for
    from your_project.auth import current_user

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        user = current_user if current_user.is_authenticated else None
        try:
            grant = server.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if "login" in grant.interactions:
            return redirect(url_for('login', next=request.url))

        if request.method == 'GET':
            scope = grant.client.get_allowed_scope(grant.request.payload.scope)

            # You may add a function to extract scope into a list of scopes
            # with rich information, e.g.
            scopes = describe_scope(scope)  # returns [{'key': 'email', 'icon': '...'}]
            return render_template(
                'authorize.html',
                grant=grant,
                user=user,
                scopes=scopes,
            )

        confirmed = request.form['confirm']
        if confirmed:
            # granted by resource owner
            return server.create_authorization_response(grant=grant, grant_user=user)

        # denied by resource owner
        return server.create_authorization_response(grant=grant, grant_user=None)

This is a simple demo, the real case should be more complex. There is a little
more complex demo in https://github.com/authlib/example-oauth2-server.

To let Authlib know if the user must give their consent, pass an
:class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin` to
``get_consent_grant`` instead of the user. Its ``is_consent_needed`` method
adds ``"consent"`` to ``grant.interactions``. :ref:`flask_odic_max_age` shows a
complete example.

The token endpoint is much easier:

.. code-block:: python

    @app.route('/oauth/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()

However, the routes will not work properly. We need to register supported
grants for them.


Register Error URIs
-------------------

To create a better developer experience for debugging, it is suggested that
you create some documentation for errors. Here is a list of built-in
:ref:`specs/rfc6749-errors`.

You can design a documentation page with a description of each error. For
instance, there is a web page for ``invalid_client``:

.. code-block:: text

   https://developer.your-company.com/errors#invalid-client

In this case, you can register the error URI with ``OAUTH2_ERROR_URIS``
configuration:

.. code-block:: python

   OAUTH2_ERROR_URIS = [
      ('invalid_client', 'https://developer.your-company.com/errors#invalid-client'),
      # other error URIs
   ]

If there is no ``OAUTH2_ERROR_URIS``, the error response will not contain any
``error_uri`` data.

.. invisible-code-block: python

    from authlib.oauth2.rfc6749 import grants

    server.register_grant(grants.ClientCredentialsGrant)
    db.create_all()
    client = Client(client_id="client-id", client_secret="client-secret")
    client.set_client_metadata({"grant_types": ["client_credentials"], "scope": "profile"})
    db.session.add(client)
    db.session.commit()

    response = app.test_client().post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        auth=("client-id", "client-secret"),
    )
    assert response.status_code == 200, response.json
    assert Token.query.filter_by(access_token=response.json["access_token"]).first()
