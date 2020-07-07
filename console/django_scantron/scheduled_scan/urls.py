from django.conf.urls import url
from django_scantron.scheduled_scan.views import ScheduledScanListView


urlpatterns = [
    url(r"^$", ScheduledScanListView.as_view()),
    url(r"^scheduled_scan/$", ScheduledScanListView.as_view(), name="scheduled_scan_list"),
]
