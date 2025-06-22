.. _jws_guide:

JSON Web Signature (JWS)
========================

.. module:: authlib.jose
    :noindex:

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JSON-based
data structures.

.. important::

    We are splitting the ``jose`` module into a separated package. You may be
    interested in joserfc_.

.. _joserfc: https://jose.authlib.org/en/dev/guide/jws/


There are two types of JWS Serializations:

1. JWS Compact Serialization
2. JWS JSON Serialization

The JWS Compact Serialization represents digitally signed or MACed
content as a compact, URL-safe string. An example (with line breaks
for display purposes only)::

    eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
    .
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
    .
    dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

There are two types of JWS JSON Serialization syntax:

1. General JWS JSON Serialization Syntax
2. Flattened JWS JSON Serialization Syntax

An example on General JWS JSON Serialization Syntax (with line breaks
within values for display purposes only)::

    {
      "payload":
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures":[
        {"protected":"eyJhbGciOiJSUzI1NiJ9",
         "header":{"kid":"2010-12-29"},
         "signature":
           "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ
            mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb
            KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl
            b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES
            c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX
            LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},
        {"protected":"eyJhbGciOiJFUzI1NiJ9",
         "header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
         "signature":
           "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
            lSApmWQxfKTUJqPP3-Kg6NU1Q"}]
    }

An example on Flattened JWS JSON Serialization Syntax (with line breaks
within values for display purposes only)::

    {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
     }

A JWS requires JWA to work properly. The algorithms for JWS are provided
in :ref:`specs/rfc7518`.

Compact Serialize and Deserialize
---------------------------------

Generate a JWS compact serialization would be easy with
:meth:`JsonWebSignature.serialize_compact`, build a JWS instance with JWA::

    from authlib.jose import JsonWebSignature

    jws = JsonWebSignature()
    # alg is a required parameter name
    protected = {'alg': 'HS256'}
    payload = b'example'
    secret = b'secret'
    jws.serialize_compact(protected, payload, secret)

There are other ``alg`` that you could use. Here is a full list of available
algorithms:

1. HS256, HS384, HS512
2. RS256, RS384, RS512
3. ES256, ES384, ES512, ES256K
4. PS256, PS384, PS512
5. EdDSA

For example, a JWS with RS256 requires a private PEM key to sign the JWS::

    jws = JsonWebSignature(algorithms=['RS256'])
    protected = {'alg': 'RS256'}
    payload = b'example'
    with open('private.pem', 'rb') as f:
        secret = f.read()
    jws.serialize_compact(protected, payload, secret)

To deserialize a JWS Compact Serialization, use
:meth:`JsonWebSignature.deserialize_compact`::

    # if it is a RS256, we use public RSA key
    with open('public.pem', 'rb') as f:
        key = f.read()
    data = jws.deserialize_compact(s, key)
    jws_header = data['header']
    payload = data['payload']

.. important::

    The above method is susceptible to a signature bypass described in CVE-2016-10555.
    It allows mixing symmetric algorithms and asymmetric algorithms. You should never
    combine symmetric (HS) and asymmetric (RS, ES, PS) signature schemes.

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

    claims = jws.deserialize_compact(token, load_key)


A ``key`` can be dynamically loaded, if you don't know which key to be used::

    def load_key(header, payload):
        kid = header['kid']
        return get_key_by_kid(kid)

    jws.deserialize_compact(s, load_key)

The result of the ``deserialize_compact`` is a dict, which contains ``header``
and ``payload``. The value of the ``header`` is a :class:`JWSHeader`.

Using **JWK** for keys? Find how to use JWK with :ref:`jwk_guide`.

JSON Serialize and Deserialize
------------------------------

:meth:`JsonWebSignature.serialize_json` is used to generate a JWS JSON Serialization,
:meth:`JsonWebSignature.deserialize_json` is used to extract a JWS JSON Serialization.
The usage is the same as "Compact Serialize and Deserialize", the only difference is
the "header"::

    # Flattened JSON serialization header syntax
    header = {'protected': {'alg': 'HS256'}, 'header': {'cty': 'JWT'}}
    key = b'secret'
    payload = b'example'
    jws.serialize_json(header, payload, key)

    # General JSON serialization header syntax
    header = [{'protected': {'alg': 'HS256'}, 'header': {'cty': 'JWT'}}]
    jws.serialize_json(header, payload, key)

For general JSON Serialization, there may be many signatures, each signature
can use its own key, in this case the dynamical key would be useful::

    def load_private_key(header, payload):
        kid = header['kid']
        return get_private_key(kid)

    header = [
        {'protected': {'alg': 'HS256'}, 'header': {'kid': 'foo'}},
        {'protected': {'alg': 'RS256'}, 'header': {'kid': 'bar'}},
    ]
    data = jws.serialize_json(header, payload, load_private_key)
    # data is a dict

    def load_public_key(header, payload):
        kid = header['kid']
        return get_public_key(kid)

    jws.deserialize_json(data, load_public_key)

Actually, there is a :meth:`JsonWebSignature.serialize` and
:meth:`JsonWebSignature.deserialize`, which can automatically serialize
and deserialize Compact and JSON Serializations.

The result of the ``deserialize_json`` is a dict, which contains ``header``
and ``payload``. The value of the ``header`` is a :class:`JWSHeader`.

Using **JWK** for keys? Find how to use JWK with :ref:`jwk_guide`.

Header Parameter Names
~~~~~~~~~~~~~~~~~~~~~~

:class:`JsonWebSignature` has a validation on header parameter names. It will
first check if the parameter name is in "Registered Header Parameter Names"
defined by RFC7515 `Section 4.1`_. Then it will check if the parameter name is
in your defined private headers.

In this case, if there are header parameter names out of the registered header
parameter names scope, you can pass the names::

    private_headers = ['h1', 'h2']
    jws = JsonWebSignature(private_headers=private_headers)

.. _`Section 4.1`: https://tools.ietf.org/html/rfc7515#section-4.1
