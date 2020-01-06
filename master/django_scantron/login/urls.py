from django.contrib.auth.views import LoginView
from django.conf.urls import url

urlpatterns = [url(r"^login/", LoginView.as_view(template_name="django_scantron/login.html"), name="login")]
