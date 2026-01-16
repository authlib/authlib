.. _jose:

JOSE Guide
==========

This part of the documentation contains information on the JOSE implementation.
It includes:

1. JSON Web Signature (JWS)
2. JSON Web Encryption (JWE)
3. JSON Web Key (JWK)
4. JSON Web Algorithm (JWA)
5. JSON Web Token (JWT)

.. versionchanged:: 1.7
    We are deprecating ``authlib.jose`` module in favor of joserfc_.

.. _joserfc: https://jose.authlib.org/en/

Usage
-----

A simple example on how to use JWT with Authlib::

    from authlib.jose import jwt

    with open('private.pem', 'rb') as f:
        key = f.read()

    payload = {'iss': 'Authlib', 'sub': '123', ...}
    header = {'alg': 'RS256'}
    s = jwt.encode(header, payload, key)

Guide
-----

Follow the documentation below to find out more in detail.

.. toctree::
    :maxdepth: 2

    jws
    jwe
    jwk
    jwt
