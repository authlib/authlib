.. _jwk_guide:

JSON Web Key (JWK)
==================

.. deprecated:: 1.7
    ``authlib.jose`` will be removed in Authlib 2.0. Use joserfc_ instead.
    :ref:`joserfc_upgrade` explains how to migrate.

.. _joserfc: https://jose.authlib.org/en/

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
be found on :rfc:`7517#section-4`.
