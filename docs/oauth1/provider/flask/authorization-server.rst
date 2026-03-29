Authorization Server
====================

The Authorization Server provides several endpoints for temporary credentials,
authorization, and issuing token credentials. When the resource owner (user)
grants the authorization, this server will issue a token credential to the
client.

.. versionchanged:: v1.0.0
    We have removed built-in SQLAlchemy integrations.


Resource Owner
--------------

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods.

A resource owner MUST implement ``get_user_id()`` method::

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)

        def get_user_id(self):
            return self.id

Client
------

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**
- Client RSA Public Key (if RSA-SHA1 signature method supported)

Developers MUST implement the missing methods of ``authlib.oauth1.ClientMixin``, take an
example of Flask-SQAlchemy::

    from authlib.oauth1 import ClientMixin

    class Client(ClientMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        client_id = db.Column(db.String(48), index=True)
        client_secret = db.Column(db.String(120), nullable=False)
        default_redirect_uri = db.Column(db.Text, nullable=False, default='')
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

        def get_default_redirect_uri(self):
            return self.default_redirect_uri

        def get_client_secret(self):
            return self.client_secret

        def get_rsa_public_key(self):
            return None

A client is registered by a user (developer) on your website. Get a deep
inside with :class:`~authlib.oauth1.rfc5849.ClientMixin` API reference.

Temporary Credentials
---------------------

A temporary credential is used to exchange a token credential. It is also
known as "request token and secret". Since it is temporary, it is better to
save them into cache instead of database. A cache instance should have these
methods:

- ``.get(key)``
- ``.set(key, value, expires=None)``
- ``.delete(key)``

A cache can be a memcache, redis or something else. If cache is not available,
developers can also implement it with database. For example, using SQLAlchemy::

    from authlib.oauth1 import TemporaryCredentialMixin

    class TemporaryCredential(TemporaryCredentialMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')
        client_id = db.Column(db.String(48), index=True)
        oauth_token = db.Column(db.String(84), unique=True, index=True)
        oauth_token_secret = db.Column(db.String(84))
        oauth_verifier = db.Column(db.String(84))
        oauth_callback = db.Column(db.Text, default='')

        def get_client_id(self):
            return self.client_id

        def get_redirect_uri(self):
            return self.oauth_callback

        def check_verifier(self, verifier):
            return self.oauth_verifier == verifier

        def get_oauth_token(self):
            return self.oauth_token

        def get_oauth_token_secret(self):
            return self.oauth_token_secret


Token Credentials
-----------------

A token credential is used to access resource owners' resources. Unlike
OAuth 2, the token credential will not expire in OAuth 1. This token credentials
are supposed to be saved into a persist database rather than a cache.

Developers MUST implement :class:`~authlib.oauth1.rfc5849.TokenCredentialMixin`
missing methods. Here is an example of SQLAlchemy integration::

    from authlib.oauth1 import TokenCredentialMixin

    class TokenCredential(TokenCredentialMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')
        client_id = db.Column(db.String(48), index=True)
        oauth_token = db.Column(db.String(84), unique=True, index=True)
        oauth_token_secret = db.Column(db.String(84))

        def get_oauth_token(self):
            return self.oauth_token

        def get_oauth_token_secret(self):
            return self.oauth_token_secret


Timestamp and Nonce
-------------------

The nonce value MUST be unique across all requests with the same timestamp,
client credentials, and token combinations. Authlib Flask integration has a
built-in validation with cache.

If cache is not available, developers can use a database, here is an example of
using SQLAlchemy::

    class TimestampNonce(db.Model):
        __table_args__ = (
            db.UniqueConstraint(
                'client_id', 'timestamp', 'nonce', 'oauth_token',
                name='unique_nonce'
            ),
        )
        id = db.Column(db.Integer, primary_key=True)
        client_id = db.Column(db.String(48), nullable=False)
        timestamp = db.Column(db.Integer, nullable=False)
        nonce = db.Column(db.String(48), nullable=False)
        oauth_token = db.Column(db.String(84))


Define A Server
---------------

Authlib provides a ready to use
:class:`~authlib.integrations.flask_oauth1.AuthorizationServer`
which has built-in tools to handle requests and responses::

    from authlib.integrations.flask_oauth1 import AuthorizationServer

    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    server = AuthorizationServer(app, query_client=query_client)

It can also be initialized lazily with init_app::

    server = AuthorizationServer()
    server.init_app(app, query_client=query_client)

It is strongly suggested that you use a cache. In this way, you
don't have to re-implement a lot of the missing methods.

There are other configurations. It works well without any changes. Here is a
list of them:

================================== ===============================================
OAUTH1_TOKEN_GENERATOR             A string of module path for importing a
                                   function to generate ``oauth_token``
OAUTH1_TOKEN_SECRET_GENERATOR      A string of module path for importing a
                                   function to generate ``oauth_token_secret``.
OAUTH1_TOKEN_LENGTH                If ``OAUTH1_TOKEN_GENERATOR`` is not
                                   configured, a random function will generate
                                   the given length of ``oauth_token``. Default
                                   value is ``42``.
OAUTH1_TOKEN_SECRET_LENGTH         A random function will generate the given
                                   length of ``oauth_token_secret``. Default
                                   value is ``48``.
================================== ===============================================

These configurations are used to create the ``token_generator`` function. But
you can pass the ``token_generator`` when initializing the AuthorizationServer::

    def token_generator():
        return {
            'oauth_token': random_string(20),
            'oauth_token_secret': random_string(46)
        }

    server = AuthorizationServer(
        app,
        query_client=query_client,
        token_generator=token_generator
    )

Server Hooks
------------

There are missing hooks that should be ``register_hook`` to AuthorizationServer.
There are helper functions for registering hooks. If cache is available, you
can take the advantage with::

    from authlib.integrations.flask_oauth1.cache import (
        register_nonce_hooks,
        register_temporary_credential_hooks
    )

    register_nonce_hooks(server, cache)
    register_temporary_credential_hooks(server, cache)

If cache is not available, developers MUST register the hooks with the database we
defined above::

    # check if nonce exists

    def exists_nonce(nonce, timestamp, client_id, oauth_token):
        q = TimestampNonce.query.filter_by(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
        )
        if oauth_token:
            q = q.filter_by(oauth_token=oauth_token)
        rv = q.first()
        if rv:
            return True

        item = TimestampNonce(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
            oauth_token=oauth_token,
        )
        db.session.add(item)
        db.session.commit()
        return False
    server.register_hook('exists_nonce', exists_nonce)

    # hooks for temporary credential

    def create_temporary_credential(token, client_id, redirect_uri):
        item = TemporaryCredential(
            client_id=client_id,
            oauth_token=token['oauth_token'],
            oauth_token_secret=token['oauth_token_secret'],
            oauth_callback=redirect_uri,
        )
        db.session.add(item)
        db.session.commit()
        return item

    def get_temporary_credential(oauth_token):
        return TemporaryCredential.query.filter_by(oauth_token=oauth_token).first()

    def delete_temporary_credential(oauth_token):
        q = TemporaryCredential.query.filter_by(oauth_token=oauth_token)
        q.delete(synchronize_session=False)
        db.session.commit()

    def create_authorization_verifier(credential, grant_user, verifier):
        credential.user_id = grant_user.id  # assuming your end user model has `.id`
        credential.oauth_verifier = verifier
        db.session.add(credential)
        db.session.commit()
        return credential

    server.register_hook('create_temporary_credential', create_temporary_credential)
    server.register_hook('get_temporary_credential', get_temporary_credential)
    server.register_hook('delete_temporary_credential', delete_temporary_credential)
    server.register_hook('create_authorization_verifier', create_authorization_verifier)

For both cache and database temporary credential, Developers MUST register a
``create_token_credential`` hook::

    def create_token_credential(token, temporary_credential):
        credential = TokenCredential(
            oauth_token=token['oauth_token'],
            oauth_token_secret=token['oauth_token_secret'],
            client_id=temporary_credential.get_client_id()
        )
        credential.user_id = temporary_credential.user_id
        db.session.add(credential)
        db.session.commit()
        return credential

    server.register_hook('create_token_credential', create_token_credential)


Server Implementation
---------------------

It is ready to create the endpoints for authorization and issuing tokens.
Let's start with the temporary credentials endpoint, which is used for clients
to fetch a temporary credential::

    @app.route('/initiate', methods=['POST'])
    def initiate_temporary_credential():
        return server.create_temporary_credentials_response()

The endpoint for resource owner authorization. OAuth 1 Client will redirect
user to this authorization page, so that resource owner can grant or deny this
request::

    @app.route('/authorize', methods=['GET', 'POST'])
    def authorize():
        # make sure that user is logged in for yourself
        if request.method == 'GET':
            try:
                req = server.check_authorization_request()
                return render_template('authorize.html', req=req)
            except OAuth1Error as error:
                return render_template('error.html', error=error)

        granted = request.form.get('granted')
        if granted:
            grant_user = current_user
        else:
            grant_user = None

        try:
            return server.create_authorization_response(grant_user=grant_user)
        except OAuth1Error as error:
            return render_template('error.html', error=error)

Then the final token endpoint. OAuth 1 Client will use the given temporary
credential and the ``oauth_verifier`` authorized by resource owner to exchange
the token credential::

    @app.route('/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()
