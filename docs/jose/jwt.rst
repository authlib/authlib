.. _jwt_guide:

JSON Web Token (JWT)
====================

.. important::

    We are splitting the ``jose`` module into a separated package. You may be
    interested in joserfc_.

.. _joserfc: https://jose.authlib.org/en/dev/guide/jwt/

.. module:: authlib.jose
    :noindex:

JSON Web Token (JWT) is structured by :ref:`specs/rfc7515` or :ref:`specs/rfc7516`
with certain payload claims. The JWT implementation in Authlib has all
built-in algorithms via :ref:`specs/rfc7518`, it can also load private/public
keys of :ref:`specs/rfc7517`::

    >>> from authlib.jose import jwt
    >>> header = {'alg': 'RS256'}
    >>> payload = {'iss': 'Authlib', 'sub': '123', ...}
    >>> private_key = read_file('private.pem')
    >>> s = jwt.encode(header, payload, private_key)
    >>> public_key = read_file('public.pem')
    >>> claims = jwt.decode(s, public_key)
    >>> print(claims)
    {'iss': 'Authlib', 'sub': '123', ...}
    >>> print(claims.header)
    {'alg': 'RS256', 'typ': 'JWT'}
    >>> claims.validate()

The imported ``jwt`` is an instance of :class:`JsonWebToken`. It has all
supported JWS algorithms, and it can handle JWK automatically. When
:meth:`JsonWebToken.encode` a payload, JWT will check payload claims for
security, if you really want to expose them, you can always turn it off
via ``check=False``.

.. important::
    JWT payload with JWS is not encrypted, it is just signed. Anyone can
    extract the payload without any private or public keys. Adding sensitive
    data like passwords, social security numbers in JWT payload is not safe
    if you are going to send them in a non-secure connection.

    You can also use JWT with JWE which is encrypted. But this feature is not
    mature, documentation is not provided yet.

JWT Encode
----------

``jwt.encode`` is the method to create a JSON Web Token string. It encodes the
payload with the given ``alg`` in header::

    >>> from authlib.jose import jwt
    >>> header = {'alg': 'RS256'}
    >>> payload = {'iss': 'Authlib', 'sub': '123', ...}
    >>> private_key = read_file('private.pem')
    >>> s = jwt.encode(header, payload, private_key)

The available keys in headers are defined by :ref:`specs/rfc7515`.

JWT Decode
----------

``jwt.decode`` is the method to translate a JSON Web Token string into the
dict of the payload::

    >>> from authlib.jose import jwt
    >>> public_key = read_file('public.pem')
    >>> claims = jwt.decode(s, public_key)

.. important::

   This decoding method is insecure. By default ``jwt.decode`` parses the alg header.
   This allows symmetric macs and asymmetric signatures. If both are allowed a signature bypass described in CVE-2016-10555 is possible.

   See the following section for a mitigation.


The returned value is a :class:`JWTClaims`, check the next section to
validate claims value.

JWT with limited Algorithms
---------------------------

There are cases that we don't want to support all the ``alg`` values,
especially when decoding a token. In this case, we can pass a list
of supported ``alg`` into :class:`JsonWebToken`::

    >>> from authlib.jose import JsonWebToken
    >>> jwt = JsonWebToken(['RS256'])

.. important::

    You should never combine symmetric (HS) and asymmetric (RS, ES, PS) signature schemes.
    When both are allowed a signature bypass described in CVE-2016-10555 is possible.

    If you must support both protocols use a custom key loader which provides a different
    keys for different methods.

Load a different ``key`` for symmetric and asymmetric signatures::

    def load_key(header, payload):
        if header['alg'] == 'RS256':
            return rsa_pub_key
        elif header['alg'] == 'HS256':
            return shared_secret
        else:
            raise UnsupportedAlgorithmError()

    claims = jwt.decode(token, load_key)



JWT Payload Claims Validation
-----------------------------

:meth:`JsonWebToken.decode` accepts 3 claims-related parameters: ``claims_cls``,
``claims_option`` and ``claims_params``. The default ``claims_cls`` is
:class:`JWTClaims`. The ``decode`` method returns::

    >>> JWTClaims(payload, header, options=claims_options, params=claims_params)

Claims validation is actually handled by :meth:`JWTClaims.validate`, which
validates payload claims with ``claims_option`` and ``claims_params``. For
standard JWTClaims, ``claims_params`` value is not used, but it is used in
:class:`~authlib.oidc.core.IDToken`.

Here is an example of ``claims_option``::

    {
        "iss": {
            "essential": True,
            "values": ["https://example.com", "https://example.org"]
        },
        "sub": {
            "essential": True
            "value": "248289761001"
        },
        "jti": {
            "validate": validate_jti
        }
    }

It is a dict configuration, the option key is the name of a claim.

- **essential**: this value is REQUIRED.
- **values**: claim value can be any one in the values list.
- **value**: claim value MUST be the same value.
- **validate**: a function to validate the claim value.


Use dynamic keys
----------------

When ``.encode`` and ``.decode`` a token, there is a ``key`` parameter to use.
This ``key`` can be the bytes of your PEM key, a JWK set, and a function.

There are cases that you don't know which key to use to ``.decode`` the token.
For instance, you have a JWK set::

    jwks = {
      "keys": [
        { "kid": "k1", ...},
        { "kid": "k2", ...},
      ]
    }

And in the token, it has a ``kid=k2`` in the header part, if you pass ``jwks`` to
the ``key`` parameter, Authlib will auto resolve the correct key::

    jwt.decode(s, key=jwks, ...)

It is also possible to resolve the correct key by yourself::

    def resolve_key(header, payload):
        return my_keys[header['kid']]

    jwt.decode(s, key=resolve_key)

For ``.encode``, if you pass a JWK set, it will randomly pick a key and assign its
``kid`` into the header.
