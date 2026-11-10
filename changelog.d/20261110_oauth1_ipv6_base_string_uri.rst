Fixed
~~~~~

- OAuth 1.0a base string URI normalization now excludes the default port
  (80 for HTTP, 443 for HTTPS) for IPv6 hosts, as required by
  :rfc:`5849#section-3.4.1.2`.
