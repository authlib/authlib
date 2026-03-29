.. _jwe_guide:

JSON Web Encryption (JWE)
=========================

.. module:: authlib.jose
    :noindex:

JSON Web Encryption (JWE) represents encrypted content using
JSON-based data structures.

.. important::

    We are splitting the ``jose`` module into a separated package. You may be
    interested in joserfc_.

.. _joserfc: https://jose.authlib.org/en/dev/guide/jwe/

There are two types of JWE Serializations:

1. JWE Compact Serialization
2. JWE JSON Serialization

Authlib has only implemented the **Compact Serialization**. This feature
is not mature yet, use at your own risk.

The JWE Compact Serialization represents encrypted content as a compact,
URL-safe string. This string is:

    BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    BASE64URL(JWE Encrypted Key) || '.' ||
    BASE64URL(JWE Initialization Vector) || '.' ||
    BASE64URL(JWE Ciphertext) || '.' ||
    BASE64URL(JWE Authentication Tag)

An example (with line breaks for display purposes only)::

    eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
    .
    OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
    ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
    Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
    mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
    1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
    6UklfCpIMfIjf7iGdXKHzg
    .
    48V1_ALb6US04U3b
    .
    5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
    SdiwkIr3ajwQzaBtQD_A
    .
    XFBoMYUZodetZdvTiFvSkQ

A JWE requires JWA to work properly. The algorithms for JWE are provided
in :ref:`specs/rfc7518`.

Compact Serialize and Deserialize
---------------------------------

Generate a JWE compact serialization would be easy with
:meth:`JsonWebEncryption.serialize_compact`, build a JWE instance with JWA::

    from authlib.jose import JsonWebEncryption

    jwe = JsonWebEncryption()
    protected = {'alg': 'RSA-OAEP', 'enc': 'A256GCM'}
    payload = b'hello'
    with open('rsa_public.pem', 'rb') as f:
        key = f.read()

    s = jwe.serialize_compact(protected, payload, key)

There are two required algorithms in protected header: ``alg`` and ``enc``.

The available ``alg`` list:

1. RSA1_5, RSA-OAEP, RSA-OAEP-256
2. A128KW, A192KW, A256KW
3. A128GCMKW, A192GCMKW, A256GCMKW

The available ``enc`` list:

1. A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
2. A128GCM, A192GCM, A256GCM

More ``alg`` and ``enc`` will be added in the future.

It is also available to compress the payload with ``zip`` header::

    protected = {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'zip': 'DEF'}
    s = jwe.serialize_compact(protected, payload, key)

To deserialize a JWE Compact Serialization, use
:meth:`JsonWebEncryption.deserialize_compact`::

    with open('rsa_private.pem', 'rb') as f:
        key = f.read()

    data = jwe.deserialize_compact(s, key)
    jwe_header = data['header']
    payload = data['payload']

The result of the ``deserialize_compact`` is a dict, which contains ``header``
and ``payload``.

Using **JWK** for keys? Find how to use JWK with :ref:`jwk_guide`.
