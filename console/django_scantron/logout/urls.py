from django.contrib.auth.views import LogoutView
from django.conf.urls import url

urlpatterns = [url(r"^logout/", LogoutView.as_view(next_page="/login"), name="logout")]
