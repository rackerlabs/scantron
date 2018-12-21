"""scantron_dir URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin

from django_scantron.login.urls import urlpatterns as login_urls
from django_scantron.logout.urls import urlpatterns as logout_urls
from django_scantron.results.urls import urlpatterns as results_urls

# from django_scantron.scan.urls import urlpatterns as scan_urls
from django_scantron.scheduled_scan.urls import urlpatterns as scheduled_scan_urls

# from django_scantron.user.urls import urlpatterns as user_urls

# Import the separate API URLs.
from django_scantron.api.urls import urlpatterns as api_urls

ur = []
ur += login_urls
ur += logout_urls
ur += results_urls
# ur += scan_urls
ur += scheduled_scan_urls
# ur += user_urls


if not hasattr(settings, "URL_PREFIX"):
    settings.URL_PREFIX = ""

urlpatterns = [
    url(r"^scantron-admin/", admin.site.urls),  # Provide minimal obfuscation for admin panel.
    url(r"^%s" % settings.URL_PREFIX, include(ur)),
    url(r"^api/", include(api_urls)),
]
