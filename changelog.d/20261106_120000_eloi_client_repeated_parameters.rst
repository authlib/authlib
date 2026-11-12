Fixed
~~~~~

- The Requests and HTTPX OAuth 2 clients send all the values of the
  ``resource`` (:rfc:`8707`) and ``audience`` (:rfc:`8693`) parameters. They
  used to send only the last one. ``fetch_token`` and ``refresh_token`` also
  accept a list for these parameters. :pr:`1010`
