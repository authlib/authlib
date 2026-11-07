Authorization Server
====================

.. meta::
    :description: How to create a Django OAuth 2.0 Authorization server with
        Authlib. Learn the required concepts in OAuth 2.0 Authorization server.

The Authorization Server provides several endpoints for authorization, issuing
tokens, refreshing tokens and revoking tokens. When the resource owner (user)
grants the authorization, this server will issue an access token to the client.

Before creating the authorization server, we need to understand several
concepts:

Resource Owner
--------------

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods.

In this documentation, we will use the ``django.contrib.auth.models.User`` as
an example.

Client
------

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**
- Client Token Endpoint Authentication Method

A user (developer) registers a client on the website. Implement
the missing methods of :class:`~authlib.oauth2.rfc6749.ClientMixin`:

.. code-block:: python

    import secrets

    from authlib.common.encoding import to_bytes

    class OAuth2Client(Model, ClientMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, unique=True, db_index=True)
        client_secret = CharField(max_length=48, blank=True)
        client_name = CharField(max_length=120)
        # space separated list of redirect URIs
        redirect_uris = TextField(default='')
        default_redirect_uri = TextField(blank=False, default='')
        scope = TextField(default='')
        response_type = TextField(default='')
        grant_type = TextField(default='')
        token_endpoint_auth_method = CharField(max_length=120, default='')

        # RFC 7591 §2 defines more client metadata fields.

        def get_client_id(self):
            return self.client_id

        def get_default_redirect_uri(self):
            return self.default_redirect_uri

        def get_allowed_scope(self, scope):
            if not scope:
                return ''
            allowed = set(scope_to_list(self.scope))
            return list_to_scope([s for s in scope.split() if s in allowed])

        def check_redirect_uri(self, redirect_uri):
            if redirect_uri == self.default_redirect_uri:
                return True
            return redirect_uri in self.redirect_uris.split()

        def check_client_secret(self, client_secret):
            return secrets.compare_digest(
                to_bytes(self.client_secret), to_bytes(client_secret)
            )

        def check_endpoint_auth_method(self, method, endpoint):
            if endpoint == 'token':
              return self.token_endpoint_auth_method == method
            # TODO: developers can update this check method
            return True

        def check_response_type(self, response_type):
            allowed = self.response_type.split()
            return response_type in allowed

        def check_grant_type(self, grant_type):
            allowed = self.grant_type.split()
            return grant_type in allowed

Token
-----

Tokens are used to access the users' resources. A token is issued with a
valid duration, limited scopes and etc. It contains at least:

- **access_token**: a token to authorize the http requests.
- **refresh_token**: (optional) a token to exchange a new access token
- **client_id**: this token is issued to which client
- **expires_at**: when will this token expired
- **scope**: a limited scope of resources that this token can access

A token belongs to a resource owner. Implement
the missing methods of :class:`~authlib.oauth2.rfc6749.TokenMixin`:

.. code-block:: python

    import time

    def now_timestamp():
        return int(time.time())

    class OAuth2Token(Model, TokenMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, db_index=True)
        token_type = CharField(max_length=40)
        access_token = CharField(max_length=255, unique=True, null=False)
        refresh_token = CharField(max_length=255, db_index=True)
        scope = TextField(default='')
        revoked = BooleanField(default=False)
        issued_at = IntegerField(null=False, default=now_timestamp)
        expires_in = IntegerField(null=False, default=0)

        def get_client_id(self):
            return self.client_id

        def get_scope(self):
            return self.scope

        def get_expires_in(self):
            return self.expires_in

        def get_expires_at(self):
            return self.issued_at + self.expires_in

        def check_client(self, client):
            return self.client_id == client.get_client_id()

        def is_expired(self):
            if not self.expires_in:
                return False

            return self.get_expires_at() < now_timestamp()

        def is_revoked(self):
            return self.revoked

        def get_user(self):
            return self.user

        def get_client(self):
            return OAuth2Client.objects.get(client_id=self.client_id)

Server
------

Authlib provides a ready to use :class:`~authlib.integrations.django_oauth2.AuthorizationServer`
which has built-in tools to handle requests and responses:

.. code-block:: python

    from authlib.integrations.django_oauth2 import AuthorizationServer

    server = AuthorizationServer(OAuth2Client, OAuth2Token)

The Authorization Server has to provide endpoints:

1. authorization endpoint if it supports ``authorization_code`` or ``implicit``
   grant types
2. token endpoint to issue tokens

The ``AuthorizationServer`` has provided built-in methods to handle these endpoints:

.. code-block:: python

    from django.contrib.auth.views import redirect_to_login
    from django.shortcuts import render
    from django.views.decorators.http import require_http_methods

    # use ``server.create_authorization_response`` to handle authorization endpoint

    def authorize(request):
        user = request.user if request.user.is_authenticated else None
        try:
            grant = server.get_consent_grant(request, end_user=user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if "login" in grant.interactions:
            return redirect_to_login(request.get_full_path())

        if request.method == 'GET':
            scope = grant.client.get_allowed_scope(grant.request.payload.scope)
            context = dict(grant=grant, client=grant.client, scope=scope, user=request.user)
            return render(request, 'authorize.html', context)

        if is_user_confirmed(request):
            # granted by resource owner
            return server.create_authorization_response(request, grant=grant, grant_user=request.user)

        # denied by resource owner
        return server.create_authorization_response(request, grant=grant, grant_user=None)

    # use ``server.create_token_response`` to handle token endpoint

    @require_http_methods(["POST"])  # we only allow POST for token endpoint
    def issue_token(request):
        return server.create_token_response(request)

To let Authlib know if the user must give their consent, pass an
:class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin` to
``get_consent_grant`` instead of the user. Its ``is_consent_needed`` method
adds ``"consent"`` to ``grant.interactions``. :ref:`django_oidc_max_age` shows a
complete example.

For now, you have set up the authorization server. But it won't work since it doesn't
support any grant types yet. Let's head over to the next chapter.
