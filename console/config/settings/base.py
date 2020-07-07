"""
Django settings for scantron project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""
import environ

# JSON-based secrets module.
# ------------------------------------------------------------------------------
import json
import os

from django.core.exceptions import ImproperlyConfigured

ROOT_DIR = environ.Path(__file__) - 3  # (console/config/settings/base.py - 3 = scantron/)
APPS_DIR = ROOT_DIR.path("django_scantron")  # scantron/console/django_scantron

# scantron_secrets.json sits in the root of the scantron folder.
with open(os.path.join(str(ROOT_DIR), "scantron_secrets.json")) as fh:
    secrets_environment = os.environ["DJANGO_SETTINGS_MODULE"].split(".")[-1]
    print(f"[*] Loading [ {secrets_environment} ] scantron_secrets.json")
    SECRETS = json.loads(fh.read())


def get_secret(setting, secrets=SECRETS):
    """
    Get the secret variable or return explicit exception.
    """
    try:
        if os.environ["DJANGO_SETTINGS_MODULE"] == "config.settings.local":
            return secrets["local"][setting]
        else:
            return secrets["production"][setting]

    except KeyError:
        error_msg = f"Set the {setting} environment variable"
        raise ImproperlyConfigured(error_msg)


# ------------------------------------------------------------------------------

# APP CONFIGURATION
# ------------------------------------------------------------------------------
DJANGO_APPS = [
    # Default Django apps:
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Admin
    "django.contrib.admin",
]

THIRD_PARTY_APPS = [
    "crispy_forms",  # Form layouts.
    "django_extensions",  # Django extensions.
    "django_filters",  # Search filters for Django REST Framework.
    "django_saml2_auth",  # SAML support.
    "recurrence",  # Used to configure periodic scans.
    "rest_framework",  # Django REST Framework.
    "rest_framework.authtoken",  # Enable token authentication for Django REST Framework.
    "drf_yasg",  # Django Rest Framework Swagger and ReDoc support.
    # "django_baker"  # Django baker is used to create CRUD files for each model.
]

# Apps specific for this project go here.
LOCAL_APPS = ["django_scantron"]

# See: https://docs.djangoproject.com/en/dev/ref/settings/#installed-apps
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# EMAIL CONFIGURATION
# ------------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = get_secret("EMAIL_HOST")
EMAIL_PORT = get_secret("EMAIL_PORT")
EMAIL_HOST_USER = get_secret("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = get_secret("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = get_secret("EMAIL_USE_TLS")


# MANAGER CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#admins
ADMINS = [("""Admin""", "admin@localhost")]

# See: https://docs.djangoproject.com/en/dev/ref/settings/#managers
MANAGERS = ADMINS

# DATABASE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": get_secret("DATABASE_NAME"),
        "HOST": get_secret("DATABASE_HOST"),
        "PORT": get_secret("DATABASE_PORT"),
        "USER": get_secret("DATABASE_USER"),
        "PASSWORD": get_secret("DATABASE_PASSWORD"),
    }
}

# GENERAL CONFIGURATION
# ------------------------------------------------------------------------------
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret("SECRET_KEY")

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# TIME_ZONE = 'UTC'
TIME_ZONE = "America/Chicago"

# See: https://docs.djangoproject.com/en/dev/ref/settings/#language-code
LANGUAGE_CODE = "en-us"

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-i18n
USE_I18N = True

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-l10n
USE_L10N = True

# See: https://docs.djangoproject.com/en/dev/ref/settings/#use-tz
USE_TZ = True

SESSION_COOKIE_AGE = 36000  # 10 hours

# TEMPLATE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#templates
TEMPLATES = [
    {
        # See: https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-TEMPLATES-BACKEND
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-dirs
        "DIRS": [str(APPS_DIR.path("templates"))],
        "APP_DIRS": True,
        "OPTIONS": {
            # See: https://docs.djangoproject.com/en/dev/ref/settings/#template-context-processors
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                # Your stuff: custom template context processors go here
            ]
        },
    }
]

# STATIC FILE CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#static-root
STATIC_ROOT = "/var/www/static"

# See: https://docs.djangoproject.com/en/dev/ref/settings/#static-url
STATIC_URL = "/static/"

# See: https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#std:setting-STATICFILES_DIRS
STATICFILES_DIRS = [
    str(APPS_DIR.path("static/scantron")),  # console/django_scantron/static/scantron/
    str(ROOT_DIR.path("static")),  # webapp/static/
]

# See: https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#staticfiles-finders
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
]

# MEDIA CONFIGURATION
# ------------------------------------------------------------------------------
# See: https://docs.djangoproject.com/en/dev/ref/settings/#media-root
# MEDIA_ROOT =

# See: https://docs.djangoproject.com/en/dev/ref/settings/#media-url
# MEDIA_URL = ''

# URL Configuration
# ------------------------------------------------------------------------------
ROOT_URLCONF = "config.urls"

# See: https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = "config.wsgi.application"

# PASSWORD STORAGE SETTINGS
# ------------------------------------------------------------------------------
# See https://docs.djangoproject.com/en/dev/topics/auth/passwords/#using-argon2-with-django
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.BCryptPasswordHasher",
]

# PASSWORD VALIDATION
# https://docs.djangoproject.com/en/dev/ref/settings/#auth-password-validators
# ------------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_REDIRECT_URL = "/"

# Your common stuff: Below this line define 3rd party library settings
# -------------------------------------------------------------------------------
# Django REST Framework
REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
        # 'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ),
    # Token Authentication.
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
}

# SAML
# https://github.com/fangli/django-saml2-auth
# fmt: off
# SAML2_AUTH = {
#     # Metadata is required, choose either remote url or local file path.
#     "METADATA_AUTO_CONF_URL": "",
#     "METADATA_LOCAL_FILE_PATH": "",

#     # Optional settings below.
#     # Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be
#     # overwritten if you have parameter ?next= specificed in the login URL.
#     "DEFAULT_NEXT_URL": "/",

#     # Create a new Django user when a new user logs in. Defaults to True.
#     "CREATE_USER": False,

#     "NEW_USER_PROFILE": {
#         "USER_GROUPS": [],  # The default group name when a new user logs in.
#         "ACTIVE_STATUS": True,  # The default active status for new users.
#         "STAFF_STATUS": False,  # The staff status for new users.
#         "SUPERUSER_STATUS": False,  # The superuser status for new users.
#     },

#     # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
#     "ATTRIBUTES_MAP": {
#         "email": "Email",
#         "username": "Username",
#         "first_name": "FirstName",
#         "last_name": "LastName",
#     },

#     "TRIGGER": {
#         "CREATE_USER": "path.to.your.new.user.hook.method",
#         "BEFORE_LOGIN": "path.to.your.login.hook.method",
#     },

#     # Custom URL to validate incoming SAML requests against.
#     "ASSERTION_URL": "",

#     # Populates the Issuer element in authn request.
#     "ENTITY_ID": "",

#     # Sets the Format property of authn NameIDPolicy element.
#     "NAME_ID_FORMAT": "None",

#     # Set this to True if you are running a Single Page Application (SPA) with Django Rest Framework (DRF), and are
#     # using JWT authentication to authorize client users.
#     "USE_JWT": False,

#     # Redirect URL for the client if you are using JWT auth with DRF.
#     "FRONTEND_URL": "",
# }
# fmt: on
