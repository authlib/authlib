Protect Resources
=================

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from django.http import JsonResponse
    from authlib.integrations.django_oauth1 import ResourceProtector
    require_oauth = ResourceProtector(Client, TokenCredential)

    @require_oauth
    def user_api(request):
        user = request.oauth1_credential.user
        return JsonResponse(dict(username=user.username))

The ``require_oauth`` decorator will add a ``oauth1_credential`` to ``request``
parameter. This ``oauth1_credential`` is an instance of the Token model.
