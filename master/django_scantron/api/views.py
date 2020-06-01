# Standard Python libraries.
import datetime
import pytz

# Third party Python libraries.
from django.conf import settings
from django.http import Http404
import redis
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAdminUser, IsAuthenticated
import rq

# Custom Python libraries.
from django_scantron.api.serializers import (
    AgentSerializer,
    GloballyExcludedTargetSerializer,
    ScanCommandSerializer,
    ScanSerializer,
    ScheduledScanSerializer,
    SiteSerializer,
)
from django_scantron.models import (
    Agent,
    GloballyExcludedTarget,
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


class ListRetrieveUpdateViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet
):
    """A viewset that provides list, retrieve, and update actions. To use it, override the class and set the .queryset
    and .serializer_class attributes.

    https://www.django-rest-framework.org/api-guide/viewsets/#custom-viewset-base-classes
    """

    pass


class DefaultsMixin(object):
    """Default settings for view pagination and filtering."""

    paginate_by = 25
    paginate_by_param = "page_size"
    max_paginate_by = 100


class AgentViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Agent Model."""

    model = Agent
    serializer_class = AgentSerializer
    permission_classes = (IsAuthenticated, IsAdminUser)


class GloballyExcludedTargetViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for GloballyExcludedTarget Model."""

    model = GloballyExcludedTarget
    serializer_class = GloballyExcludedTargetSerializer
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScanCommandViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for ScanCommand Model."""

    model = ScanCommand
    serializer_class = ScanCommandSerializer
    permission_classes = (IsAuthenticated, IsAdminUser)


class SiteViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Site Model."""

    model = Site
    serializer_class = SiteSerializer
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScanViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Scan Model."""

    model = Scan
    serializer_class = ScanSerializer
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScheduledScanViewSet(ListRetrieveUpdateViewSet, DefaultsMixin):
    """API CRUD operations for ScheduledScan Model."""

    model = ScheduledScan
    serializer_class = ScheduledScanSerializer

    def partial_update(self, request, pk=None, **kwargs):

        try:

            # Extract the json payload.
            body = self.request.data

            if body["scan_status"] in ["started", "pause", "paused", "cancel", "cancelled", "completed", "error"]:

                # Filter only the applicable ScheduledScans for the agent.  Prevents an agent modifying another agent's
                # ScheduledScan information.
                scheduled_scan_dict = (
                    ScheduledScan.objects.filter(scan_agent=request.user).filter(pk=pk).values()[0]
                )  # noqa

                # Update the scheduled_scan_dict with the most recent scan_status state from the PUT request.  When
                # originally querying above, the old state is passed to utility.py unless it is updated.
                scheduled_scan_dict["scan_status"] = body["scan_status"]

                # Create a redis connection object.
                redis_conn = redis.Redis(host="127.0.0.1", port=6379, db=0)

                # Create a redis queue object.
                q = rq.Queue(connection=redis_conn)

                # Queue up the scheduled_scan_dict to be processed by utility.py.
                job = q.enqueue(utility.process_scan_status_change, scheduled_scan_dict)  # noqa

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
                .filter(scan_status__in=["pending", "pause", "cancel"])
                .filter(start_datetime__lt=now_datetime)
            )

        # Allow agents to update scan information.
        elif http_method in ("PATCH"):
            queryset = ScheduledScan.objects.filter(scan_agent=user)

        # Return empty queryset.
        else:
            queryset = []

        return queryset
