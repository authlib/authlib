.. _jwk_guide:

JSON Web Key (JWK)
==================

.. important::

    We are splitting the ``jose`` module into a separated package. You may be
    interested in joserfc_.

.. _joserfc: https://jose.authlib.org/en/dev/guide/jwk/

.. module:: authlib.jose
    :noindex:

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure
that represents a cryptographic key. An example would help a lot::

    {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "iss-a"
    }

This is an Elliptic Curve Public Key represented by JSON data structure.
:meth:`JsonWebKey.import_key` will convert PEM, JSON, bytes into these keys:

1. :class:`OctKey`
2. :class:`RSAKey`
3. :class:`ECKey`
4. :class:`OKPKey`

Algorithms for ``kty`` (Key Type) is defined by :ref:`specs/rfc7518`.
Import a key with::

    from authlib.jose import JsonWebKey

    key_data = read_file('public.pem')
    key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

    key.as_dict()
    key.as_json()

You may pass extra parameters into ``import_key`` method, available parameters can
be found on RFC7517 `Section 4`_.

.. _`Section 4`: https://tools.ietf.org/html/rfc7517#section-4
