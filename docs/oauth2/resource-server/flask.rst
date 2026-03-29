.. _flask_oauth2_resource_protector:

Flask Integration
=================

Protects users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Authlib offers a **decorator** to protect your API endpoints::

    from flask import jsonify
    from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

    require_oauth = ResourceProtector()

    # only bearer token is supported currently
    require_oauth.register_token_validator(MyBearerTokenValidator())

When the resource server has no access to the ``Token`` model (database), and
there is an introspection token endpoint in authorization server, you can
:ref:`require_oauth_introspection`.

Here is the way to protect your users' resources::

    @app.route('/user')
    @require_oauth('profile')
    def user_profile():
        # if Token model has `.user` foreign key
        user = current_token.user
        return jsonify(user)

If the resource is not protected by a scope, omit the argument::

    @app.route('/user')
    @require_oauth
    def user_profile():
        user = current_token.user
        return jsonify(user)

The ``current_token`` is a proxy to the Token model you have defined above.
Since there is a ``user`` relationship on the Token model, we can access this
``user`` with ``current_token.user``.

If the decorator is not your favorite, there is a ``with`` statement for you::

    @app.route('/user')
    def user_profile():
        with require_oauth.acquire('profile') as token:
            user = token.user
            return jsonify(user)

.. _flask_oauth2_multiple_scopes:

Multiple Scopes
---------------

.. versionchanged:: v1.0

You can apply multiple scopes to one endpoint in **AND**, **OR** and mix modes.
Here are some examples:

.. code-block:: python

    @app.route('/profile')
    @require_oauth(['profile email'])
    def user_profile():
        user = current_token.user
        return jsonify(user)

It requires the token containing both ``profile`` and ``email`` scope.

.. code-block:: python

    @app.route('/profile')
    @require_oauth(['profile', 'email']')
    def user_profile():
        user = current_token.user
        return jsonify(user)

It requires the token containing either ``profile`` or ``email`` scope.

It is also possible to mix **AND** and **OR** logic. e.g.::

    @app.route('/profile')
    @require_oauth(['profile email', 'user'])
    def user_profile():
        user = current_token.user
        return jsonify(user)

This means if the token will be valid if:

1. token contains both ``profile`` and ``email`` scope
2. or token contains ``user`` scope

Optional ``require_oauth``
--------------------------

There is one more parameter for ``require_oauth`` which is used to serve
public endpoints::

    @app.route('/timeline')
    @require_oauth(optional=True)
    def timeline_api():
        if current_token:
            return get_user_timeline(current_token.user)
        return get_public_timeline()

MethodView & Flask-Restful
--------------------------

You can also use the ``require_oauth`` decorator in ``flask.views.MethodView``
and ``flask_restful.Resource``::

    from flask.views import MethodView

    class UserAPI(MethodView):
        decorators = [require_oauth('profile')]


    from flask_restful import Resource

    class UserAPI(Resource):
        method_decorators = [require_oauth('profile')]
