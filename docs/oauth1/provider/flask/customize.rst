Customize Signature Methods
===========================

The ``AuthorizationServer`` and ``ResourceProtector`` only support **HMAC-SHA1**
signature method by default. There are three signature methods built-in, which
can be enabled with the configuration:

.. code-block:: python

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA1', 'PLAINTEXT', 'RSA-SHA1']

It is also possible to extend the signature methods. For example, you want to
create a **HMAC-SHA256** signature method:

.. code-block:: python

    import base64
    import hashlib
    import hmac

    from authlib.common.encoding import to_bytes, to_unicode
    from authlib.oauth1.rfc5849 import signature
    from authlib.oauth1.rfc5849.util import escape

    def verify_hmac_sha256(request):
        text = signature.generate_signature_base_string(request)

        key = escape(request.client_secret or '')
        key += '&'
        key += escape(request.token_secret or '')

        sig = hmac.new(to_bytes(key), to_bytes(text), hashlib.sha256)
        expected = to_unicode(base64.b64encode(sig.digest()))
        return hmac.compare_digest(expected, request.signature)

    AuthorizationServer.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )
    ResourceProtector.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )

Then add this method into **SUPPORTED_SIGNATURE_METHODS**:

.. code-block:: python

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA256']

With this configuration, your server will support **HMAC-SHA256** signature
method only. If you want to support more methods, add them to the list.

.. invisible-code-block: python

    from types import SimpleNamespace

    request = SimpleNamespace(
        method="POST",
        uri="https://example.com/initiate",
        params=[("oauth_consumer_key", "client-id")],
        headers={},
        client_secret="client-secret",
        token_secret=None,
    )
    base_string = signature.generate_signature_base_string(request)
    digest = hmac.new(b"client-secret&", to_bytes(base_string), hashlib.sha256).digest()
    request.signature = to_unicode(base64.b64encode(digest))
    assert verify_hmac_sha256(request)
    request.signature = "forged"
    assert not verify_hmac_sha256(request)
