"""
Local settings

- Run in Debug mode

- Use console backend for emails

- Add Django Debug Toolbar
"""
# export DJANGO_SETTINGS_MODULE="scantron.settings.local"
from .base import *  # noqa


# DEBUG
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#debug
DEBUG = True

# Mail settings
# ------------------------------------------------------------------------------
EMAIL_HOST = "127.0.0.1"
EMAIL_PORT = 1025
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
EMAIL_USE_TLS = True

# django-debug-toolbar
# ------------------------------------------------------------------------------
# MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware', ]  # noqa
# INSTALLED_APPS += ['debug_toolbar', ]  # noqa


INTERNAL_IPS = ["127.0.0.1"]

# Your local stuff: Below this line define 3rd party library settings
# ------------------------------------------------------------------------------
