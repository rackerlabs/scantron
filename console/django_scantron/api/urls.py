from django.conf.urls import url
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions, routers

from django_scantron.api import views

# Create a router and register our viewsets with it.
# base_name requirement: http://www.django-rest-framework.org/api-guide/routers/#usage
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"engines", views.EngineViewSet, base_name="engines")
router.register(r"engine_pools", views.EnginePoolViewSet, base_name="engine_pools")
router.register(
    r"globally_excluded_targets", views.GloballyExcludedTargetViewSet, base_name="globally_excluded_targets"
)
router.register(r"scan_commands", views.ScanCommandViewSet, base_name="scan_commands")
router.register(r"scans", views.ScanViewSet, base_name="scans")
router.register(r"scheduled_scans", views.ScheduledScanViewSet, base_name="scheduled_scans")
router.register(r"sites", views.SiteViewSet, base_name="sites")

schema_view = get_schema_view(
    openapi.Info(
        title="Scantron API",
        default_version="v1",
        description="Scantron API documentation",
        terms_of_service="https://github.com/rackerlabs/scantron",
        contact=openapi.Contact(email="https://github.com/rackerlabs/scantron"),
        license=openapi.License(name="Apache License, Version 2.0"),
    ),
    public=False,
    permission_classes=(permissions.IsAuthenticated,),  # comma needed inside parenthesis.
)

urlpatterns = [
    url(r"^swagger(?P<format>\.json|\.yaml)$", schema_view.without_ui(cache_timeout=0), name="schema-json"),
    url(r"^swagger/$", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    url(r"^redoc/$", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]

urlpatterns += router.urls
