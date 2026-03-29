Authorization Server
====================

The Authorization Server provides several endpoints for temporary credentials,
authorization, and issuing token credentials. When the resource owner (user)
grants the authorization, this server will issue a token credential to the
client.

Currently, Authlib Django implementation is using cache a lot, which means
you don't have to handle temporary credentials, timestamp and nonce yourself,
they are all built-in.

To create an authorization server, only **Client** and **Token** models are
required::

    from your_project.models import Client, Token
    from authlib.integrations.django_oauth1 import CacheAuthorizationServer

    authorization_server = CacheAuthorizationServer(Client, Token)


Resource Owner
--------------

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods. In
Django, we can use the built in contrib user::

    from django.contrib.auth.models import User

Client
------

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**
- Client RSA Public Key (if RSA-SHA1 signature method supported)

Authlib has no implementation for client model in Django. You need to implement
it yourself::

    from django.db import models
    from django.contrib.auth.models import User
    from authlib.oauth1 import ClientMixin

    class Client(models.Model, ClientMixin):
        user = models.ForeignKey(User, on_delete=CASCADE)
        client_id = models.CharField(max_length=48, unique=True, db_index=True)
        client_secret = models.CharField(max_length=48, blank=True)
        default_redirect_uri = models.TextField(blank=False, default='')

        def get_default_redirect_uri(self):
            return self.default_redirect_uri

        def get_client_secret(self):
            return self.client_secret

        def get_rsa_public_key(self):
            return None

A client is registered by a user (developer) on your website. Get a deep
inside with :class:`~authlib.oauth1.rfc5849.ClientMixin` API reference.

Token
-----

A token credential is used to access resource owners' resources. Unlike
OAuth 2, the token credential will not expire in OAuth 1. This token credentials
are supposed to be saved into a persist database rather than a cache.

Here is an example of how it looks in Django::

    from django.db import models
    from django.contrib.auth.models import User
    from authlib.oauth1 import TokenCredentialMixin

    class Token(models.Model, TokenCredentialMixin):
        user = models.ForeignKey(User, on_delete=CASCADE)
        client_id = models.CharField(max_length=48, db_index=True)
        oauth_token = models.CharField(max_length=84, unique=True, db_index=True)
        oauth_token_secret = models.CharField(max_length=84)

        def get_oauth_token(self):
            return self.oauth_token

        def get_oauth_token_secret(self):
            return self.oauth_token_secret

Server Implementation
---------------------

It is ready to create the endpoints for authorization and issuing tokens.
Let's start with the temporary credentials endpoint, which is used for clients
to fetch a temporary credential::

    from django.views.decorators.http import require_http_methods

    @require_http_methods(["POST"])
    def initiate_temporary_credential(request):
        return server.create_temporary_credential_response(request)

The endpoint for resource owner authorization. OAuth 1 Client will redirect
user to this authorization page, so that resource owner can grant or deny this
request::

    from django.shortcuts import render

    def authorize(request):
        # make sure that user is logged in for yourself
        if request.method == 'GET':
            try:
                req = server.check_authorization_request(request)
                context = {'req': req}
                return render(request, 'authorize.html', context)
            except OAuth1Error as error:
                context = {'error': error}
                return render(request, 'error.html', context)

        granted = request.POST.get('granted')
        if granted:
            grant_user = request.user
        else:
            grant_user = None

        try:
            return server.create_authorization_response(request, grant_user)
        except OAuth1Error as error:
            context = {'error': error}
            return render(request, 'error.html', context)

Then the final token endpoint. OAuth 1 Client will use the given temporary
credential and the ``oauth_verifier`` authorized by resource owner to exchange
the token credential::

    from django.views.decorators.http import require_http_methods

    @require_http_methods(["POST"])
    def issue_token(request):
        return server.create_token_response(request)

At last, you need to register these views into url patterns.
