Breaking changes
~~~~~~~~~~~~~~~~

- The OpenID Connect implicit and hybrid flows only accept the ``fragment``
  and ``form_post`` response modes, per OAuth 2.0 Multiple Response Type
  Encoding Practices §5. Other values, ``query`` included, get an
  ``invalid_request`` error in the fragment, before the user consent. An
  unknown value used to raise a ``ValueError``. :pr:`980`
- Without the ``MultipleResponseTypes`` extension, the OpenID Connect implicit
  and hybrid flows send ``access_denied`` in the fragment, like the other
  errors, even with ``response_mode=form_post``. :pr:`1000`
- ``IssuerParameter.add_issuer_parameter`` receives an
  ``AuthorizationResponse`` and adds ``iss`` to its ``params``. It used to
  change the ``Location`` header of the framework response. Custom grants must
  return an ``AuthorizationResponse`` to get ``iss``. :pr:`987`

Added
~~~~~

- The ``MultipleResponseTypes`` extension implements OAuth 2.0 Multiple
  Response Type Encoding Practices. Clients choose the response mode of any
  authorization grant with ``response_mode``, errors included. The server
  accepts the modes of ``response_modes_supported``, and never sends tokens in
  the query. See :doc:`/oauth2/specs/multiple-response-types`. :pr:`985`
- The ``FormPost`` extension implements OAuth 2.0 Form Post Response Mode for
  any authorization grant. A grant can use it by default with
  ``RESPONSE_MODE = "form_post"``. See :ref:`specs/form_post`. :pr:`986`
- ``NoneResponseTypeGrant`` supports ``response_type=none``. The client
  receives ``state``, and no code or token. :pr:`988`
- Grants and endpoints return an ``OAuth2Response``, such as a
  ``JsonResponse``, a ``RedirectResponse`` or an ``AuthorizationResponse``.
  :pr:`983` :pr:`984`

Fixed
~~~~~

- The ``form_post`` response sends the parameters unchanged, and forbids
  caching with ``Cache-Control: no-store``. The parameters used to be
  percent-encoded, so the client could receive a modified ``state`` or
  ``error_description``. :pr:`980`
- The OpenID Connect implicit and hybrid flows return ``state`` when the user
  denies the request. :pr:`980`
- ``IssuerParameter`` adds ``iss`` to the fragment of fragment responses, and
  to the form of ``form_post`` responses. It used to put it in the query of
  fragment responses, and to omit it in ``form_post`` responses and in the
  errors of the consent page. :pr:`987`
- The hybrid flow sends its errors in the fragment instead of the query, for a
  missing ``nonce``, an unsupported scope and an unauthorized
  ``response_type``.

Deprecated
~~~~~~~~~~

- Using ``response_mode`` with the OpenID Connect implicit and hybrid grants
  without the ``MultipleResponseTypes`` extension is deprecated. Register it
  with ``server.register_extension(MultipleResponseTypes())``. It will stop
  working in 1.11. :pr:`985`
- ``DEFAULT_RESPONSE_MODE`` of the OpenID Connect implicit and hybrid grants
  is deprecated. Use ``RESPONSE_MODE``. ``create_response_mode_response`` of
  ``authlib.oidc.core.grants.util`` is deprecated too. Return an
  ``AuthorizationResponse``. Both will be removed in 1.11. :pr:`986`
- Returning a ``(status_code, body, headers)`` tuple from a grant or an
  endpoint is deprecated. Return an ``OAuth2Response``. Unpacking an
  ``OAuth2Response`` as such a tuple is deprecated too, and will stop working
  in 1.11. Use its ``status_code``, ``body`` and ``headers`` attributes.
  :pr:`983`
