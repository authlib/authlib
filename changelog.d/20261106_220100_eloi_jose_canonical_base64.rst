Breaking changes
~~~~~~~~~~~~~~~~

- ``authlib.jose`` rejects JWS and JWE segments that are not canonical
  base64url, such as a signature with padding or a trailing newline. Strip a
  token read from a file before decoding it.
