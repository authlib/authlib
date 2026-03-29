.. _django_resource_server:

Django Integration
==================

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources in Django::

    from authlib.integrations.django_oauth2 import ResourceProtector, BearerTokenValidator
    from django.http import JsonResponse

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))

    @require_oauth('profile')
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

If the resource is not protected by a scope, omit the argument::

    @require_oauth
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

The decorator ``require_oauth`` will add an ``oauth_token`` property on ``request``,
which is the instance of current in-use Token.

Multiple Scopes
---------------

.. versionchanged:: v1.0

You can apply multiple scopes to one endpoint in **AND**, **OR** and mix modes.
Here are some examples:

.. code-block:: python

    @require_oauth(['profile email'])
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

It requires the token containing both ``profile`` and ``email`` scope.

.. code-block:: python

    @require_oauth(['profile', 'email'])
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

It requires the token containing either ``profile`` or ``email`` scope.


It is also possible to mix **AND** and **OR** logic. e.g.::

    @app.route('/profile')
    @require_oauth(['profile email', 'user'])
    def user_profile(request):
        user = request.oauth_token.user
        return JsonResponse(dict(sub=user.pk, username=user.username))

This means if the token will be valid if:

1. token contains both ``profile`` and ``email`` scope
2. or token contains ``user`` scope

Optional ``require_oauth``
--------------------------

There is one more parameter for ``require_oauth`` which is used to serve
public endpoints::

    @require_oauth(optional=True)
    def timeline_api(request):
        if request.oauth_token:
            return get_user_timeline(request.oauth_token.user)
        return get_public_timeline(request)
