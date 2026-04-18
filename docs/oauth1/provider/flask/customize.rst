Customize Signature Methods
===========================

The ``AuthorizationServer`` and ``ResourceProtector`` only support **HMAC-SHA1**
signature method by default. There are three signature methods built-in, which
can be enabled with the configuration::

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA1', 'PLAINTEXT', 'RSA-SHA1']

It is also possible to extend the signature methods. For example, you want to
create a **HMAC-SHA256** signature method::

    import hmac
    from authlib.common.encoding import to_bytes
    from authlib.oauth1.rfc5849 import signature

    def verify_hmac_sha256(request):
        text = signature.generate_signature_base_string(request)

        key = escape(request.client_secret or '')
        key += '&'
        key += escape(request.token_secret or '')

        sig = hmac.new(to_bytes(key), to_bytes(text), hashlib.sha256)
        return binascii.b2a_base64(sig.digest())[:-1]

    AuthorizationServer.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )
    ResourceProtector.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )

Then add this method into **SUPPORTED_SIGNATURE_METHODS**::

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA256']

With this configuration, your server will support **HMAC-SHA256** signature
method only. If you want to support more methods, add them to the list.
