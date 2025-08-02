"""Support for OAuth 2.0 Protected Resource Metadata .well-known url"""
from authlib.common.urls import urlparse


def get_well_known_url(issuer, external=False, suffix="oauth-protected-resource"):
    """Get well-known URI with issuer via `Section 3.1`_.

    .. _`Section 3.1`: https://tools.ietf.org/html/rfc9728#section-3.1

    :param issuer: URL of the issuer
    :param external: return full external url or not
    :param suffix: well-known URI suffix for RFC9728
    :return: URL
    """
    parsed = urlparse.urlparse(issuer)
    path = parsed.path
    if path and path != "/":
        url_path = f"/.well-known/{suffix}{path}"
    else:
        url_path = f"/.well-known/{suffix}"
    if not external:
        return url_path
    return parsed.scheme + "://" + parsed.netloc + url_path
