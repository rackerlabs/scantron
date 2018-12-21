import datetime

from rest_framework import viewsets

from django_scantron.api.serializers import (
    AgentSerializer,
    NmapCommandSerializer,
    ScanGETSerializer,
    ScanPOSTSerializer,
    ScheduledScanSerializer,
    SiteSerializer,
)
from django_scantron.models import Agent, NmapCommand, Scan, ScheduledScan, Site


def get_current_time():
    """Retrieve a Django compliant pre-formated datetimestamp."""

    now_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return now_datetime


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
    serializer_class = ScanGETSerializer

    # https://www.reddit.com/r/django/comments/6nhgsf/trouble_posting_model_containing_foreign_key_in/
    def get_serializer_class(self):

        http_method = self.request.method

        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method." % self.__class__.__name__
        )

        # Return different serializer if the request is a POST.
        if http_method in ("POST"):
            serializer_class = ScanPOSTSerializer
            return serializer_class
        else:
            return self.serializer_class

    def get_queryset(self):
        http_method = self.request.method
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = Scan.objects.all()

        # Filter results based off user, 'Pending' scan status, and start_time for HTTP GET requests.
        elif http_method == "GET":
            now_datetime = get_current_time()
            queryset = (
                Scan.objects.filter(site__scan_agent__scan_agent=user)
                .filter(scan_status="pending")
                .filter(start_time__lt=now_datetime)
            )

        # Allow agents to update scan information.
        elif http_method in ("PATCH"):
            queryset = Scan.objects.filter(site__scan_agent__scan_agent=user)

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

        # Filter results based off user, 'Pending' scan status, and start_time for HTTP GET requests.
        elif http_method == "GET":
            queryset = (
                ScheduledScan.objects.filter(scan_agent=user)
                .filter(scan_status="pending")
                .filter(start_time__lt=now_datetime)
            )

        # Allow agents to update scan information.
        elif http_method in ("PATCH"):
            queryset = ScheduledScan.objects.filter(scan_agent=user)

        # Return empty queryset.
        else:
            queryset = []

        return queryset
