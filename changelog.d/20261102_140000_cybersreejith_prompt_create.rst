Added
~~~~~

- Support ``prompt=create`` and ``prompt_values_supported`` from Initiating
  User Registration via OpenID Connect 1.0, with the ``PromptValues``
  authorization server extension. Its ``get_server_metadata`` returns the
  supported ``prompt`` values. The other values get an HTTP 400
  ``invalid_request`` error. When the list contains ``create``, it comes
  first in ``grant.interactions`` for an anonymous user. :issue:`735`
  :PR:`907`
