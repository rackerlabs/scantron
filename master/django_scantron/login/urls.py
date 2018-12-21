from django.contrib.auth import views as auth_views
from django.conf.urls import url

urlpatterns = [url(r"^login/", auth_views.login, {"template_name": "django_scantron/login.html"}, name="login")]
