Resource Servers
================

.. versionchanged:: v1.0.0
    We have removed built-in SQLAlchemy integrations.

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.integrations.flask_oauth1 import ResourceProtector, current_credential

    # we will define ``query_client``, ``query_token``, and ``exists_nonce`` later.
    require_oauth = ResourceProtector(
        app, query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )
    # or initialize it lazily
    require_oauth = ResourceProtector()
    require_oauth.init_app(
        app,
        query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )

    @app.route('/user')
    @require_oauth
    def user_profile():
        user = current_credential.user
        return jsonify(user)

The ``current_credential`` is a proxy to the Token model you have defined above.
Since there is a ``user`` relationship on the Token model, we can access this
``user`` with ``current_credential.user``.

Initialize
----------

To initialize ``ResourceProtector``, we need three functions:

1. query_client
2. query_token
3. exists_nonce

If using SQLAlchemy, the ``query_client`` could be::

    def query_client(client_id):
        # assuming ``Client`` is the model
        return Client.query.filter_by(client_id=client_id).first()

And ``query_token`` would be::

    def query_token(client_id, oauth_token):
        return TokenCredential.query.filter_by(client_id=client_id, oauth_token=oauth_token).first()

For ``exists_nonce``, if you are using cache now (as in authorization server), Authlib
has a built-in tool function::

    from authlib.integrations.flask_oauth1 import create_exists_nonce_func
    exists_nonce = create_exists_nonce_func(cache)

If using database, with SQLAlchemy it would look like::

    def exists_nonce(nonce, timestamp, client_id, oauth_token):
        q = db.session.query(TimestampNonce.nonce).filter_by(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
        )
        if oauth_token:
            q = q.filter_by(oauth_token=oauth_token)
        rv = q.first()
        if rv:
            return True

        tn = TimestampNonce(
            nonce=nonce,
            timestamp=timestamp,
            client_id=client_id,
            oauth_token=oauth_token,
        )
        db.session.add(tn)
        db.session.commit()
        return False

MethodView & Flask-Restful
--------------------------

You can also use the ``require_oauth`` decorator in ``flask.views.MethodView``
and ``flask_restful.Resource``::

    from flask.views import MethodView

    class UserAPI(MethodView):
        decorators = [require_oauth]


    from flask_restful import Resource

    class UserAPI(Resource):
        method_decorators = [require_oauth]
