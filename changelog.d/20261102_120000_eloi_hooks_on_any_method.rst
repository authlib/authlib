Breaking changes
~~~~~~~~~~~~~~~~

- Hooks run around the most derived override of a method, even when it does
  not call ``super()``. An ``after`` hook gets the result of the override. For
  instance, ``OpenIDCode`` now adds the ``id_token`` when
  ``create_token_response`` is overridden. :pr:`978`
- Only ``Hookable`` classes run hooks. A method of a mixin that is not
  ``Hookable`` no longer runs hooks, even with ``hooked``, and registering a
  hook on it raises a ``TypeError``. Make the mixin inherit from ``Hookable``.
  A mixin method that overrides a method of a ``Hookable`` class still runs
  hooks. :pr:`978`
- ``register_hook`` raises a ``TypeError`` for a static method, a class method
  or a property, and when ``hook_type`` and ``hook`` are passed by name.
  ``hooked`` raises a ``TypeError`` with custom hook names. :pr:`978`

Added
~~~~~

- Hooks can run before, after or instead of any method of a ``Hookable``
  class, such as a grant, an authorization server or a resource protector.
  Register them with a reference to the method, such as
  ``after=AuthorizationCodeGrant.validate_token_request``. Hook names such as
  ``"after_validate_token_request"`` still work. :pr:`978`

Fixed
~~~~~

- Hooks run in the order they are registered. The order used to be random.
  :pr:`978`

Deprecated
~~~~~~~~~~

- ``authlib.oauth2.rfc6749.hooks.hooked`` is deprecated and does nothing. It
  will be removed in 1.11. :pr:`978`
