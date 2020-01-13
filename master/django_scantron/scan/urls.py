from django.conf.urls import url
from django_scantron.scan.views import (
    ScanListView,
    # ScanCreateView,
    # ScanDetailView,
    # ScanUpdateView,
    # ScanDeleteView,
)


urlpatterns = [
    url(r"^$", ScanListView.as_view()),
    url(r"^scan/$", ScanListView.as_view(), name="scan_list"),
    # url(r"^scan/create/$", ScanCreateView.as_view(), name="scan_create"),
    # url(r"^scan/(?P<pk>\d+)/update/$", ScanUpdateView.as_view(), name="scan_update"),
    # url(r"^scan/(?P<pk>\d+)/delete/$", ScanDeleteView.as_view(), name="scan_delete"),
    # url(r"^scan/(?P<pk>\d+)/$", ScanDetailView.as_view(), name="scan_detail"),
]
