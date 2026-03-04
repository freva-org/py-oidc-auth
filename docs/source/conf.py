# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
from datetime import date

from py_oidc_auth import __version__

project = "py-oidc-auth"
author = "DKRZ"
copyright = f"{date.today().year}, {author}"
release = __version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx_code_tabs",
    "sphinx_copybutton",
    "sphinx_togglebutton",
    "sphinxcontrib.httpdomain",
    "sphinx_execute_code",
    "sphinx_design",
    "sphinxext.opengraph",
    "sphinx.ext.intersphinx",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "litestar": ("https://docs.litestar.dev/latest", None),
}

autodoc_mock_imports = [
    # FastAPI
    "fastapi",
    "fastapi.responses",
    "fastapi.security",
    "starlette",
    "starlette.requests",
    "starlette.responses",
    "starlette.status",
    # Flask and Quart
    "flask",
    "quart",
    # Django
    "django",
    "django.http",
    "django.shortcuts",
    "django.urls",
    "asgiref",
    "asgiref.sync",
    # Tornado
    "tornado",
    "tornado.web",
    "tornado.ioloop",
    # Litestar
    "litestar",
    "litestar.di",
    "litestar.exceptions",
    "litestar.response",
]

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False


html_static_path = ["_static"]
html_theme = "pydata_sphinx_theme"
html_logo = None
templates_path = ["_templates"]
html_favicon = os.path.join(html_static_path[0], "favicon.ico")
html_css_files = ["custom.css"]
html_theme_options = {
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/freva-org/py-oidc-auth",
            "icon": "fa-brands fa-github",
        }
    ],
    "logo": {
        "image_light": "_static/logo.png",
        "image_dark": "_static/logo.png",
        "text": "Py OpenID Connect Auth.",
    },
    "navigation_with_keys": False,
    "show_toc_level": 4,
    "collapse_navigation": False,
    "navigation_depth": 4,
    "navbar_align": "left",
    "show_nav_level": 4,
    "navbar_center": ["navbar-nav"],
    "secondary_sidebar_items": ["page-toc"],
}

html_context = {
    "github_user": "freva-org",
    "github_repo": "py-oidc-auth",
    "github_version": "main",
    "doc_path": "docs",
}
html_sidebars = {"**": ["sidebar-nav-bs"]}
html_meta = {
    "description": "Reusable OpenID Connect authentication library.",
    "keywords": "oauth2, oauth2.1, oidc, authentication, authorization, web, framework.",
    "author": "DKRZ",
    "og:title": "OpenID Connect Authentication made easy",
    "og:description": "Reusable OpenID Connect authentication library.",
    "og:type": "website",
    "og:url": "https://py-oidc-auth.readthedocs.io",
    "og:image": "https://py-oidc-auth.readthedocs.io/en/latest/_static/logo.png",
    "twitter:card": "summary_large_image",
    "twitter:title": "OpenID Connect Authentication made easy",
    "twitter:description": "Reusable OpenID Connect authentication library.",
    "twitter:image": "https://py-oidc-auth.readthedocs.io/en/latest/_static/logo.png",
}

ogp_site_url = "https://py-oidc-auth.readthedocs.io"
opg_image = "https://py-oidc-auth.readthedocs.io/en/latest/_static/logo.png"
ogp_type = "website"
ogp_custom_meta_tags = [
    '<meta name="twitter:card" content="summary_large_image">',
    '<meta name="keywords" content="oauth2, oauth2.1, oidc, authentication, authorization, web, framework">',
]

# -- Options for autosummary/autodoc output ------------------------------------
autosummary_generate = True
# autodoc_typehints = "description"
# autodoc_class_signature = "separated"
# autodoc_member_order = "groupwise"


# -- Options for autoapi -------------------------------------------------------
autoapi_type = "python"
autoapi_dirs = ["../src/py_oidc_auth"]
autoapi_keep_files = True
autoapi_root = "api"
autoapi_member_order = "groupwise"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# -- MyST options ------------------------------------------------------------

# This allows us to use ::: to denote directives, useful for admonitions
myst_enable_extensions = ["colon_fence", "linkify", "substitution"]
myst_heading_anchors = 2
myst_substitutions = {"rtd": "[Read the Docs](https://readthedocs.org/)"}

# ReadTheDocs has its own way of generating sitemaps, etc.
if not os.environ.get("READTHEDOCS"):
    extensions += ["sphinx_sitemap"]

    html_baseurl = os.environ.get("SITEMAP_URL_BASE", "http://127.0.0.1:8000/")
    sitemap_locales = [None]
    sitemap_url_scheme = "{link}"

# specifying the natural language populates some key tags
language = "en"
