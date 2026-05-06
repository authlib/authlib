import re

# Structurally validates BCP 47 language tags (RFC 5646).
# Accepts private-use tags (x-...) and standard tags (2-8 alpha + optional subtags).
# Does not validate subtags against the IANA registry.
_LANGUAGE_TAG_RE = re.compile(
    r"^(x(-[a-zA-Z0-9]{1,8})+|[a-zA-Z]{2,8}(-[a-zA-Z0-9]{1,8})*)$"
)


def is_valid_language_tag(tag):
    """Return True if tag is a structurally valid BCP 47 language tag."""
    return isinstance(tag, str) and bool(_LANGUAGE_TAG_RE.match(tag))
