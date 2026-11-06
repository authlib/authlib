Breaking changes
~~~~~~~~~~~~~~~~

- ``authlib.jose`` rejects JWS and JWE segments that are not canonical
  base64url, such as a signature with padding, extra characters, or a trailing
  newline. A token now has a single serialization, like in joserfc. Strip the
  token before decoding it if it comes from a file.
