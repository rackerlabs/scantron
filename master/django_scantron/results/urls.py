from django.conf.urls import url
from django_scantron.results import views


urlpatterns = [url(r"^results/(?P<id>\d+)$", views.retrieve_scan_file, name="retrieve_scan_file")]
