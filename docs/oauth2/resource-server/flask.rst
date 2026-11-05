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

The access token is read from the ``Authorization`` header. To also accept it
in a form-encoded request body, see :ref:`rfc6750_form_body`.

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

.. _flask_oauth2_jwt_access_tokens:

JWT access tokens
-----------------

When the authorization server issues JWT access tokens (:rfc:`9068`), the
resource server can validate them locally, without a database or an
introspection call. Subclass :class:`~authlib.oauth2.rfc9068.JWTBearerTokenValidator`
and tell it where to find the issuer's public keys::

    from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

    class MyJWTValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return app.config['AUTHORIZATION_SERVER_JWKS']

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(
        MyJWTValidator(
            issuer='https://auth.example.org',
            resource_server='https://api.example.org',
        )
    )

The validator checks the signature, the ``iss`` claim against ``issuer`` and
the ``aud`` claim against ``resource_server``, so tokens issued for another API
are rejected.

Accepting tokens from several issuers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A validator trusts one issuer. To accept tokens from an approved list of
authorization servers, keep one validator per issuer and pick the right one
from the ``iss`` claim. The ``iss`` value is read **before** the signature is
checked and is only used to select a validator: the token is still verified
with that issuer's keys, so a token that claims a trusted issuer but is signed
with another key is rejected::

    import json

    from joserfc import jws
    from joserfc.errors import JoseError
    from authlib.oauth2.rfc6750 import InvalidTokenError
    from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

    class IssuerValidator(JWTBearerTokenValidator):
        def __init__(self, issuer, jwks, resource_server):
            super().__init__(issuer, resource_server)
            self.jwks = jwks

        def get_jwks(self):
            return self.jwks

    class MultiIssuerValidator(JWTBearerTokenValidator):
        def __init__(self, resource_server, trusted_issuers):
            # trusted_issuers maps an issuer identifier to its JWKS
            super().__init__(None, resource_server)
            self.validators = {
                issuer: IssuerValidator(issuer, jwks, resource_server)
                for issuer, jwks in trusted_issuers.items()
            }

        def authenticate_token(self, token_string):
            try:
                payload = jws.extract_compact(token_string.encode()).payload
                validator = self.validators[json.loads(payload)['iss']]
            except (JoseError, ValueError, KeyError, TypeError):
                raise InvalidTokenError(
                    realm=self.realm, extra_attributes=self.extra_attributes
                )
            return validator.authenticate_token(token_string)

    require_oauth.register_token_validator(
        MultiIssuerValidator(
            'https://api.example.org',
            {
                'https://auth-a.example.org': jwks_a,
                'https://auth-b.example.org': jwks_b,
            },
        )
    )

Because each issuer has its own validator instance, nothing is shared between
requests. Fetch and cache each issuer's JWKS as described in
:class:`~authlib.oauth2.rfc9068.JWTBearerTokenValidator`.

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
