from django.conf.urls import url
from rest_framework import routers
from rest_framework_swagger.views import get_swagger_view

from django_scantron.api import views

# Create a router and register our viewsets with it.
# base_name requirement: http://www.django-rest-framework.org/api-guide/routers/#usage
router = routers.DefaultRouter()
router.register(r'agents', views.AgentViewSet, base_name='agents')
router.register(r'nmap_commands', views.NmapCommandViewSet, base_name='nmap_commands')
router.register(r'scans', views.ScanViewSet, base_name='scans')
router.register(r'scheduled_scans', views.ScheduledScanViewSet, base_name='scheduled_scans')
router.register(r'sites', views.SiteViewSet, base_name='sites')

schema_view = get_swagger_view(title='Swagger API')

urlpatterns = [
    url(r'^docs/', schema_view),
]

urlpatterns += router.urls
