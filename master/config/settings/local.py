"""
Local settings

- Run in Debug mode
- Add Django Debug Toolbar
"""
from .base import *  # noqa


# DEBUG
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#debug
DEBUG = True

# django-debug-toolbar
# ------------------------------------------------------------------------------
MIDDLEWARE += [  # noqa
    "debug_toolbar.middleware.DebugToolbarMiddleware",
]
INSTALLED_APPS += [  # noqa
    "debug_toolbar",
]


INTERNAL_IPS = ["127.0.0.1"]

# Your local stuff: Below this line define 3rd party library settings
# ------------------------------------------------------------------------------
