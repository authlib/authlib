"""Support for OAuth 2.0 Protected Resource Metadata .well-known url"""

from authlib.common.urls import urlparse


def get_well_known_url(
    resource_identifier, external=False, suffix="oauth-protected-resource"
):
    """Build the well-known metadata URL from a resource identifier
    per :rfc:`9728#section-3.1`.

    By default returns a relative path (useful for registering the route in
    your application). Set ``external=True`` to get the full URL (useful for
    clients fetching the metadata)::

        from authlib.oauth2.rfc9728 import get_well_known_url

        get_well_known_url("https://api.example.com/")
        # '/.well-known/oauth-protected-resource'

        get_well_known_url("https://api.example.com/", external=True)
        # 'https://api.example.com/.well-known/oauth-protected-resource'
    """
    parsed = urlparse.urlparse(resource_identifier)
    path = parsed.path
    if path and path != "/":
        url_path = f"/.well-known/{suffix}{path}"
    else:
        url_path = f"/.well-known/{suffix}"
    if not external:
        return url_path
    return urlparse.urlunparse(
        (parsed.scheme, parsed.netloc, url_path, "", parsed.query, "")
    )
