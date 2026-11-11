Breaking changes
~~~~~~~~~~~~~~~~

- ``IssuerParameter.add_issuer_parameter`` receives an
  ``AuthorizationResponse``, and adds ``iss`` to its ``params``. It used to
  receive the framework response and change its ``Location`` header.
  ``IssuerParameter`` no longer adds ``iss`` to the responses of custom grants
  that return a tuple or a redirection. Return an ``AuthorizationResponse``
  instead.

Fixed
~~~~~

- ``IssuerParameter`` adds ``iss`` to the fragment of fragment responses and
  to the form of ``form_post`` responses. It used to add it to the query of
  fragment responses, and to omit it in ``form_post`` responses and in the
  errors of the consent page.
