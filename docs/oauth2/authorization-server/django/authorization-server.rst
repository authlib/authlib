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

A client is registered by a user (developer) on your website; you MUST implement
the missing methods of :class:`~authlib.oauth2.rfc6749.ClientMixin`::

    class OAuth2Client(Model, ClientMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, unique=True, db_index=True)
        client_secret = CharField(max_length=48, blank=True)
        client_name = CharField(max_length=120)
        redirect_uris = TextField(default='')
        default_redirect_uri = TextField(blank=False, default='')
        scope = TextField(default='')
        response_type = TextField(default='')
        grant_type = TextField(default='')
        token_endpoint_auth_method = CharField(max_length=120, default='')

        # you can add more fields according to your own need
        # check https://tools.ietf.org/html/rfc7591#section-2

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
            return redirect_uri in self.redirect_uris

        def check_client_secret(self, client_secret):
            return self.client_secret == client_secret

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

A token is associated with a resource owner; you MUST implement
the missing methods of :class:`~authlib.oauth2.rfc6749.TokenMixin`::

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

Server
------

Authlib provides a ready to use :class:`~authlib.integrations.django_oauth2.AuthorizationServer`
which has built-in tools to handle requests and responses::

    from authlib.integrations.django_oauth2 import AuthorizationServer

    server = AuthorizationServer(OAuth2Client, OAuth2Token)

The Authorization Server has to provide endpoints:

1. authorization endpoint if it supports ``authorization_code`` or ``implicit``
   grant types
2. token endpoint to issue tokens

The ``AuthorizationServer`` has provided built-in methods to handle these endpoints::

    from django.shortcuts import render
    from django.views.decorators.http import require_http_methods

    # use ``server.create_authorization_response`` to handle authorization endpoint

    def authorize(request):
        try:
            grant = server.get_consent_grant(request, end_user=request.user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

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

For now, you have set up the authorization server. But it won't work since it doesn't
support any grant types yet. Let's head over to the next chapter.
