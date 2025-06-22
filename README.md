<a href="https://authlib.org/">
<img align="right" width="120" height="120" src="https://authlib.org/assets/logo.svg">
</a>

# Authlib

<a href="https://github.com/sponsors/lepture"><img src="https://badgen.net/badge/support/authlib/ff69b4?icon=patreon" /></a>
<a href="https://github.com/authlib/authlib/actions"><img src="https://github.com/authlib/authlib/workflows/tests/badge.svg" alt="Build Status"></a>
<a href="https://codecov.io/gh/authlib/authlib" > <img src="https://codecov.io/gh/authlib/authlib/graph/badge.svg?token=BQKzPoql9j"/></a>
<a href="https://pypi.org/project/Authlib/"><img src="https://badgen.net/pypi/v/authlib" alt="PyPI Version"></a>
<a href="https://codeclimate.com/github/authlib/authlib/maintainability"><img src="https://badgen.net/codeclimate/maintainability/authlib/authlib?icon=codeclimate" alt="Maintainability" /></a>

The ultimate Python library in building OAuth and OpenID Connect servers.
JWS, JWK, JWA, JWT are included.

Authlib is compatible with Python3.9+.

**[Migrating from `authlib.jose` to `joserfc`](https://jose.authlib.org/en/dev/migrations/authlib/)**

## Sponsors

<table>
<tr>
<td><img align="middle" width="48" src="https://avatars.githubusercontent.com/u/70178963?v=4"></td>
<td>If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at <a href="https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=authlib&utm_content=auth">auth0.com/overview</a>.</td>
</tr>
<tr>
<td><img align="middle" width="48" src="https://typlog.com/assets/icon-white.svg"></td>
<td>A blogging and podcast hosting platform with minimal design but powerful features. Host your blog and Podcast with <a href="https://typlog.com/">Typlog.com</a>.
</td>
</tr>
</table>

[**Fund Authlib to access additional features**](https://docs.authlib.org/en/latest/community/funding.html)

## Features

Generic, spec-compliant implementation to build clients and providers:

- [The OAuth 1.0 Protocol](https://docs.authlib.org/en/latest/basic/oauth1.html)
  - [RFC5849: The OAuth 1.0 Protocol](https://docs.authlib.org/en/latest/specs/rfc5849.html)
- [The OAuth 2.0 Authorization Framework](https://docs.authlib.org/en/latest/basic/oauth2.html)
  - [RFC6749: The OAuth 2.0 Authorization Framework](https://docs.authlib.org/en/latest/specs/rfc6749.html)
  - [RFC6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://docs.authlib.org/en/latest/specs/rfc6750.html)
  - [RFC7009: OAuth 2.0 Token Revocation](https://docs.authlib.org/en/latest/specs/rfc7009.html)
  - [RFC7523: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://docs.authlib.org/en/latest/specs/rfc7523.html)
  - [RFC7591: OAuth 2.0 Dynamic Client Registration Protocol](https://docs.authlib.org/en/latest/specs/rfc7591.html)
  - [RFC7592: OAuth 2.0 Dynamic Client Registration Management Protocol](https://docs.authlib.org/en/latest/specs/rfc7592.html)
  - [RFC7636: Proof Key for Code Exchange by OAuth Public Clients](https://docs.authlib.org/en/latest/specs/rfc7636.html)
  - [RFC7662: OAuth 2.0 Token Introspection](https://docs.authlib.org/en/latest/specs/rfc7662.html)
  - [RFC8414: OAuth 2.0 Authorization Server Metadata](https://docs.authlib.org/en/latest/specs/rfc8414.html)
  - [RFC8628: OAuth 2.0 Device Authorization Grant](https://docs.authlib.org/en/latest/specs/rfc8628.html)
  - [RFC9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://docs.authlib.org/en/latest/specs/rfc9068.html)
  - [RFC9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://docs.authlib.org/en/latest/specs/rfc9101.html)
  - [RFC9207: OAuth 2.0 Authorization Server Issuer Identification](https://docs.authlib.org/en/latest/specs/rfc9207.html)
- [Javascript Object Signing and Encryption](https://docs.authlib.org/en/latest/jose/index.html)
  - [RFC7515: JSON Web Signature](https://docs.authlib.org/en/latest/jose/jws.html)
  - [RFC7516: JSON Web Encryption](https://docs.authlib.org/en/latest/jose/jwe.html)
  - [RFC7517: JSON Web Key](https://docs.authlib.org/en/latest/jose/jwk.html)
  - [RFC7518: JSON Web Algorithms](https://docs.authlib.org/en/latest/specs/rfc7518.html)
  - [RFC7519: JSON Web Token](https://docs.authlib.org/en/latest/jose/jwt.html)
  - [RFC7638: JSON Web Key (JWK) Thumbprint](https://docs.authlib.org/en/latest/specs/rfc7638.html)
  - [ ] RFC7797: JSON Web Signature (JWS) Unencoded Payload Option
  - [RFC8037: ECDH in JWS and JWE](https://docs.authlib.org/en/latest/specs/rfc8037.html)
  - [ ] draft-madden-jose-ecdh-1pu-04: Public Key Authenticated Encryption for JOSE: ECDH-1PU
- [OpenID Connect 1.0](https://docs.authlib.org/en/latest/specs/oidc.html)
  - [x] OpenID Connect Core 1.0
  - [x] OpenID Connect Discovery 1.0
  - [x] OpenID Connect Dynamic Client Registration 1.0

Connect third party OAuth providers with Authlib built-in client integrations:

- Requests
  - [OAuth1Session](https://docs.authlib.org/en/latest/client/requests.html#requests-oauth-1-0)
  - [OAuth2Session](https://docs.authlib.org/en/latest/client/requests.html#requests-oauth-2-0)
  - [OpenID Connect](https://docs.authlib.org/en/latest/client/requests.html#requests-openid-connect)
  - [AssertionSession](https://docs.authlib.org/en/latest/client/requests.html#requests-service-account)
- HTTPX
  - [AsyncOAuth1Client](https://docs.authlib.org/en/latest/client/httpx.html#httpx-oauth-1-0)
  - [AsyncOAuth2Client](https://docs.authlib.org/en/latest/client/httpx.html#httpx-oauth-2-0)
  - [OpenID Connect](https://docs.authlib.org/en/latest/client/httpx.html#httpx-oauth-2-0)
  - [AsyncAssertionClient](https://docs.authlib.org/en/latest/client/httpx.html#async-service-account)
- [Flask OAuth Client](https://docs.authlib.org/en/latest/client/flask.html)
- [Django OAuth Client](https://docs.authlib.org/en/latest/client/django.html)
- [Starlette OAuth Client](https://docs.authlib.org/en/latest/client/starlette.html)
- [FastAPI OAuth Client](https://docs.authlib.org/en/latest/client/fastapi.html)

Build your own OAuth 1.0, OAuth 2.0, and OpenID Connect providers:

- Flask
  - [Flask OAuth 1.0 Provider](https://docs.authlib.org/en/latest/flask/1/)
  - [Flask OAuth 2.0 Provider](https://docs.authlib.org/en/latest/flask/2/)
  - [Flask OpenID Connect 1.0 Provider](https://docs.authlib.org/en/latest/flask/2/openid-connect.html)
- Django
  - [Django OAuth 1.0 Provider](https://docs.authlib.org/en/latest/django/1/)
  - [Django OAuth 2.0 Provider](https://docs.authlib.org/en/latest/django/2/)
  - [Django OpenID Connect 1.0 Provider](https://docs.authlib.org/en/latest/django/2/openid-connect.html)

## Useful Links

1. Homepage: <https://authlib.org/>.
2. Documentation: <https://docs.authlib.org/>.
3. Purchase Commercial License: <https://authlib.org/plans>.
4. Blog: <https://blog.authlib.org/>.
5. Twitter: <https://twitter.com/authlib>.
6. StackOverflow: <https://stackoverflow.com/questions/tagged/authlib>.
7. Other Repositories: <https://github.com/authlib>.
8. Subscribe Tidelift: [https://tidelift.com/subscription/pkg/pypi-authlib](https://tidelift.com/subscription/pkg/pypi-authlib?utm_source=pypi-authlib&utm_medium=referral&utm_campaign=links).

## Security Reporting

If you found security bugs, please do not send a public issue or patch.
You can send me email at <me@lepture.com>. Attachment with patch is welcome.
My PGP Key fingerprint is:

```
72F8 E895 A70C EBDF 4F2A DFE0 7E55 E3E0 118B 2B4C
```

Or, you can use the [Tidelift security contact](https://tidelift.com/security).
Tidelift will coordinate the fix and disclosure.

## License

Authlib offers two licenses:

1. BSD LICENSE
2. COMMERCIAL-LICENSE

Any project, open or closed source, can use the BSD license.
If your company needs commercial support, you can purchase a commercial license at
[Authlib Plans](https://authlib.org/plans). You can find more information at
<https://authlib.org/support>.
