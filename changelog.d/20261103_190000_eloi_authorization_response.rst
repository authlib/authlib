Added
~~~~~

- Authorization grants return an ``AuthorizationResponse``. It holds the
  parameters sent to the client, and the authorization server encodes them
  according to the response mode. In ``form_post`` mode, the OpenID Connect
  implicit and hybrid grants do not use it yet.
