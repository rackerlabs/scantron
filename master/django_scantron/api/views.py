import datetime
import pytz

from django.conf import settings
from rest_framework import viewsets

from django_scantron.api.serializers import (
    AgentSerializer,
    NmapCommandSerializer,
    ScanSerializer,
    ScheduledScanSerializer,
    SiteSerializer,
)

# fmt: off
from django_scantron.models import (
    Agent,
    NmapCommand,
    Scan,
    ScheduledScan,
    Site,
)
# fmt: on


def get_current_time():
    """Retrieve a Django compliant pre-formated datetimestamp."""

    datetime_tz_naive = datetime.datetime.now()
    django_timezone = settings.TIME_ZONE
    datetime_tz = pytz.timezone(django_timezone).localize(datetime_tz_naive)

    return datetime_tz


class DefaultsMixin(object):
    """Default settings for view pagination and filtering."""

    paginate_by = 25
    paginate_by_param = "page_size"
    max_paginate_by = 100


class AgentViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Agent Model."""

    model = Agent
    serializer_class = AgentSerializer

    def get_queryset(self):
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = Agent.objects.all()

        # Return empty queryset.
        else:
            queryset = []

        return queryset


class NmapCommandViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for NmapCommand Model."""

    model = NmapCommand
    serializer_class = NmapCommandSerializer

    def get_queryset(self):
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = NmapCommand.objects.all()

        # Return empty queryset.
        else:
            queryset = []

        return queryset


class SiteViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Site Model."""

    model = Site
    serializer_class = SiteSerializer

    def get_queryset(self):
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = Site.objects.all()

        # Return empty queryset.
        else:
            queryset = []

        return queryset


class ScanViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Scan Model."""

    model = Scan
    serializer_class = ScanSerializer

    def get_queryset(self):
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = Scan.objects.all()

        # Return empty queryset.
        else:
            queryset = []

        return queryset


class ScheduledScanViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for ScheduledScan Model."""

    model = ScheduledScan
    serializer_class = ScheduledScanSerializer

    def get_queryset(self):
        http_method = self.request.method
        user = self.request.user

        # Django compliant pre-formated datetimestamp.
        now_datetime = get_current_time()

        # Update last_checkin time.
        Agent.objects.filter(scan_agent=user).update(last_checkin=now_datetime)

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = ScheduledScan.objects.all()

        # Filter results based off user, "Pending" scan status, and start_datetime for HTTP GET requests.
        elif http_method == "GET":
            queryset = (
                ScheduledScan.objects.filter(scan_agent=user)
                .filter(scan_status="pending")
                .filter(start_datetime__lt=now_datetime)
            )

        # Allow agents to update scan information.
        elif http_method in ("PATCH"):
            queryset = ScheduledScan.objects.filter(scan_agent=user)

        # Return empty queryset.
        else:
            queryset = []

        return queryset
