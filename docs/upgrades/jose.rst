.. _joserfc_upgrade:

joserfc migration
=================

joserfc_ is derived from Authlib and provides a cleaner design along with
first-class type hints. We strongly recommend using ``joserfc`` instead of
the ``authlib.jose`` module.

Starting with **Authlib 1.7.0**, the ``authlib.jose`` module is deprecated and
will emit deprecation warnings. A comprehensive
`Migrating from Authlib <https://jose.authlib.org/en/migrations/authlib/>`_
guide is available in the joserfc_ documentation to help you transition.

.. _joserfc: https://jose.authlib.org/en/

The following modules are affected by this upgrade:

- ``authlib.oauth2.rfc7523``
- ``authlib.oauth2.rfc7591``
- ``authlib.oauth2.rfc7592``
- ``authlib.oauth2.rfc9068``
- ``authlib.oauth2.rfc9101``
- ``authlib.oidc.core``

Breaking Changes
----------------

A common breaking change involves the exceptions raised by the affected modules.
Since these modules now use ``joserfc``, all exceptions are ``joserfc``-based.
If your code previously caught exceptions from ``authlib.jose``, you should
update it to catch the corresponding exceptions from ``joserfc`` instead.

.. code-block:: diff

    -from authlib.jose.errors import JoseError
    +from joserfc.errors import JoseError

     try:
         do_something()
     except JoseError:
         pass

JWTAuthenticationRequest
~~~~~~~~~~~~~~~~~~~~~~~~


Starting with v1.7, ``authlib.oauth2.rfc9101.JWTAuthenticationRequest`` uses
only the recommended JWT algorithms by default. If you need to support additional
algorithms, you can explicitly include them in ``get_server_metadata``:

.. code-block:: python

    class MyJWTAuthenticationRequest(JWTAuthenticationRequest):
        def get_server_metadata(self):
            return {
                ...,
                "request_object_signing_alg_values_supported": ["RS256", ...],
            }


UserInfoEndpoint
~~~~~~~~~~~~~~~~

The signing algorithms supported by ``authlib.oidc.core.UserInfoEndpoint`` are
limited to the recommended JWT algorithms. If you need to support additional
algorithms, you can explicitly include them in ``get_supported_algorithms``:

.. code-block:: python

    class MyUserInfoEndpoint(UserInfoEndpoint):
        def get_supported_algorithms(self):
            return ["RS512"]

Deprecating Messages
--------------------

Most deprecation warnings are triggered by how keys are imported. For security
reasons, joserfc_ requires explicit key types. Instead of passing raw strings or
bytes as keys, you should return ``OctKey``, ``RSAKey``, ``ECKey``, ``OKPKey``,
or ``KeySet`` instances directly.

``get_jwt_config``
------------------

``get_jwt_config`` is converted into 3 methods:

1. ``resolve_client_private_key``
2. ``get_client_claims``
3. ``get_client_algorithm``

.. code-block:: python

    # before 1.7
    class OpenIDCode(grants.OpenIDCode):
        def get_jwt_config(self):
            return {
                'key': read_private_key_file(key_path),
                'alg': 'RS512',
                'iss': 'https://example.com',
                'exp': 3600
            }

    # authlib>=1.7
    class OpenIDCode(grants.OpenIDCode):
        def resolve_client_private_key(self, client):
            with open(jwks_file_path) as f:
                data = json.load(f)
            return KeySet.import_key_set(data)

        def get_client_claims(self, client):
            return {
                'iss': 'https://example.com',
            }
