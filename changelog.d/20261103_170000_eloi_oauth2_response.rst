Added
~~~~~

- Grants and endpoints return an ``OAuth2Response``, a ``JsonResponse`` or a
  ``RedirectResponse``. A ``before`` hook on
  ``AuthorizationServer.encode_response`` can change any response of the
  authorization server, errors included.

Deprecated
~~~~~~~~~~

- Returning a ``(status_code, body, headers)`` tuple from a grant or an
  endpoint is deprecated. Return an ``OAuth2Response`` instead.
- Using an ``OAuth2Response`` as a ``(status_code, body, headers)`` tuple is
  deprecated. This happens in an override that unpacks
  ``super().create_token_response()`` or
  ``super().create_authorization_response()``, or in a hook that reads
  ``result[1]``. Use the ``status_code``, ``body`` and ``headers``
  attributes. It will stop working in version 1.11.
