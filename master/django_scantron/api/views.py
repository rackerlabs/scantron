# Standard Python libraries.
import datetime
import pytz

# Third party Python libraries.
from django.conf import settings
from django.http import Http404, HttpResponse
import redis
from rest_framework import viewsets
import rq

# Custom Python libraries.
from django_scantron.api.serializers import (
    AgentSerializer,
    ScanCommandSerializer,
    ScanSerializer,
    ScheduledScanSerializer,
    SiteSerializer,
)
from django_scantron.models import (
    Agent,
    ScanCommand,
    Scan,
    ScheduledScan,
    Site,
)
import utility


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


class ScanCommandViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for ScanCommand Model."""

    model = ScanCommand
    serializer_class = ScanCommandSerializer

    def get_queryset(self):
        user = self.request.user

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = ScanCommand.objects.all()

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

    def partial_update(self, request, pk=None, **kwargs):

        try:
            # Filter only the applicable ScheduledScans for the agent.  Prevents an agent modifying another agent's
            # ScheduledScan information.
            obj = ScheduledScan.objects.filter(scan_agent=request.user).get(pk=pk)  # noqa

            # Extract the json payload.
            body = self.request.data

            if body["scan_status"] in ["started", "completed", "error"]:

                # Create a redis connection object.
                redis_conn = redis.Redis(host="127.0.0.1", port=6379, db=0)

                # Create a redis queue object.
                q = rq.Queue(connection=redis_conn)

                queue_object = {
                    "site_name": obj.site_name,
                    "scan_status": body["scan_status"],
                }

                job = q.enqueue(utility.process_scan_status_change, queue_object)  # noqa

            else:
                raise Http404

        except ScheduledScan.DoesNotExist:
            raise Http404

        kwargs["partial"] = True

        return self.update(request, pk, **kwargs)

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
