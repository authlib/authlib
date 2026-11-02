Breaking changes
~~~~~~~~~~~~~~~~

- Hooks run around the most derived override of a method. An ``after`` hook
  used to run when the parent method returned inside ``super()``. It now runs
  when the override returns, and it gets the result of the override. Hooks also
  run when the override does not call ``super()``. For example, ``OpenIDCode``
  now adds the ``id_token`` when ``create_token_response`` is overridden.
- Methods of a mixin that is not ``Hookable`` no longer run hooks, even with
  ``hooked``. Registering a hook on them raises a ``TypeError``. Make the
  mixin inherit from ``Hookable``. A mixin method that overrides a method of a
  ``Hookable`` class still runs hooks.
- A hook name that matches a static method, a class method or a property
  raises a ``TypeError``.
- The first two parameters of ``register_hook`` are positional-only.
  ``register_hook(hook_type=..., hook=...)`` raises a ``TypeError``.
- ``hooked`` raises a ``TypeError`` when it gets custom hook names.

Added
~~~~~

- Hooks can run before, after or instead of any method defined in a
  ``Hookable`` class, such as a grant, an authorization server or a resource
  protector. Register a hook with a
  reference to the method, such as
  ``grant.register_hook(hook, after=AuthorizationCodeGrant.validate_token_request)``.
  Hook names such as ``"after_validate_token_request"`` still work.

Deprecated
~~~~~~~~~~

- ``authlib.oauth2.rfc6749.hooks.hooked`` is deprecated and does nothing.
  Methods of a ``Hookable`` class run their hooks without it. It will be
  removed in version 1.11.
