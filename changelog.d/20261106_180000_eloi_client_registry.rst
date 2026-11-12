Added
~~~~~

- ``OAuth.remove_client(name)`` removes a registered remote application.
  :issue:`583`

Fixed
~~~~~

- Registering a remote application with a name that is already registered
  replaces it. It used to return the first client. :issue:`583`
- Registering a remote application no longer changes
  ``client_cls.OAUTH_APP_CONFIG`` or the dicts given to ``register``, such as
  ``client_kwargs``. :issue:`583`
