import warnings

import authlib
from authlib.deprecate import AuthlibDeprecationWarning

from sphinx.locale import _

# we will keep authlib.jose module until 2.0.0
warnings.simplefilter("ignore", AuthlibDeprecationWarning)

project = "Authlib"
copyright = "&copy; 2017, Hsiaoming Ltd"
author = "Hsiaoming Yang"
version = authlib.__version__
release = version

templates_path = ["_templates"]
html_static_path = ["_static"]
html_css_files = [
    "custom.css",
]
html_theme = "shibuya"

html_copy_source = False
html_show_sourcelink = False

language = "en"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
    "sphinx_design",
]

extlinks = {
    "issue": ("https://github.com/authlib/authlib/issues/%s", "issue #%s"),
    "PR": ("https://github.com/authlib/authlib/pull/%s", "pull request #%s"),
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "joserfc": ("https://jose.authlib.org/en/", None),
}
html_favicon = "_static/icon.svg"
html_theme_options = {
    "accent_color": "blue",
    "globaltoc_expand_depth": 1,
    "og_image_url": "https://authlib.org/logo.png",
    "light_logo": "_static/light-logo.svg",
    "dark_logo": "_static/dark-logo.svg",
    "twitter_site": "authlib",
    "twitter_creator": "lepture",
    "twitter_url": "https://twitter.com/authlib",
    "github_url": "https://github.com/authlib/authlib",
    "discord_url": "https://discord.gg/HvBVAeNAaV",
    "nav_links": [
        {
            "title": _("Projects"),
            "children": [
                {
                    "title": _("Authlib"),
                    "url": "https://authlib.org/",
                    "summary": _("OAuth, JOSE, OpenID, etc."),
                },
                {
                    "title": _("JOSE RFC"),
                    "url": "https://jose.authlib.org/",
                    "summary": _("JWS, JWE, JWK, and JWT."),
                },
                {
                    "title": _("OTP Auth"),
                    "url": "https://otp.authlib.org/",
                    "summary": _("One time password, HOTP/TOTP."),
                },
            ],
        },
        {"title": _("Sponsor me"), "url": "https://github.com/sponsors/lepture"},
    ],
}

html_context = {}
