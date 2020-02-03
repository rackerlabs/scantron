from django.conf.urls import url
from django_scantron.scan_command.views import ScanCommandListView, ScanCommandCreateView


urlpatterns = [
    url(r"^$", ScanCommandListView.as_view()),
    url(r"^scan_command/$", ScanCommandListView.as_view(), name="scan_command_list"),
    url(r"^scan_command/create$", ScanCommandCreateView.as_view(), name="scan_command_create"),
]
