# Standard Python libraries.
import datetime
import os
import pytz

# Third party Python libraries.
from django.conf import settings
from django.http import Http404, JsonResponse
import redis
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAdminUser, IsAuthenticated
import rq

# Custom Python libraries.
from django_scantron.api.serializers import (
    EngineSerializer,
    EnginePoolSerializer,
    GloballyExcludedTargetSerializer,
    ScanCommandSerializer,
    ScanSerializer,
    ScheduledScanSerializer,
    SiteSerializer,
)
from django_scantron.models import (
    Engine,
    EnginePool,
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


class EngineViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Engine Model."""

    model = Engine
    serializer_class = EngineSerializer
    queryset = Engine.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class EnginePoolViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for EnginePool Model."""

    model = EnginePool
    serializer_class = EnginePoolSerializer
    queryset = EnginePool.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class GloballyExcludedTargetViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for GloballyExcludedTarget Model."""

    model = GloballyExcludedTarget
    serializer_class = GloballyExcludedTargetSerializer
    queryset = GloballyExcludedTarget.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScanCommandViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for ScanCommand Model."""

    model = ScanCommand
    serializer_class = ScanCommandSerializer
    queryset = ScanCommand.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class SiteViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Site Model."""

    model = Site
    serializer_class = SiteSerializer
    queryset = Site.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScanViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """API CRUD operations for Scan Model."""

    model = Scan
    serializer_class = ScanSerializer
    queryset = Scan.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)


class ScheduledScanViewSet(ListRetrieveUpdateViewSet, DefaultsMixin):
    """API CRUD operations for ScheduledScan Model."""

    model = ScheduledScan
    serializer_class = ScheduledScanSerializer

    def partial_update(self, request, pk=None, **kwargs):

        # Any updates to this dictionary should also be updated in console/django_scantron/models.py
        scan_status_allowed_state_update_dict = {
            "pending": ["started", "error"],
            "started": ["pause", "cancel", "completed", "error"],
            "pause": ["paused", "error"],
            "paused": ["pending", "cancel", "error"],
            "cancel": ["cancelled", "error"],
            "cancelled": ["error"],
            "completed": ["error"],
            "error": ["pending"],
        }

        try:

            # Extract the json payload.
            body = self.request.data
            new_scan_status = body["scan_status"]

            if new_scan_status in ["started", "pause", "paused", "cancel", "cancelled", "completed", "error"]:

                # Filter only the applicable ScheduledScans for the engine.  Prevents an engine modifying another engine's
                # ScheduledScan information.
                scheduled_scan_dict = ScheduledScan.objects.filter(scan_engine=request.user).filter(pk=pk).values()[0]

                current_scan_status = scheduled_scan_dict["scan_status"]

                # Based off the current scan status, ensure the updated scan status is valid.
                if new_scan_status not in scan_status_allowed_state_update_dict[current_scan_status]:

                    # Convert list to a string.
                    valid_scan_states = ", ".join(scan_status_allowed_state_update_dict[current_scan_status])

                    response_dict = {
                        "detail": f"Invalid scan status change requested.  Scan status state '{current_scan_status}' "
                        f"can only transition to: {valid_scan_states}"
                    }

                    return JsonResponse(response_dict)

                # Setup folder directories.
                scan_results_dir = "/home/scantron/console/scan_results"
                pending_files_dir = os.path.join(scan_results_dir, "pending")
                completed_files_dir = os.path.join(scan_results_dir, "complete")
                cancelled_files_dir = os.path.join(scan_results_dir, "cancelled")

                if new_scan_status == "cancelled":
                    # Move scan files to the "cancelled" directory for historical purposes.
                    utility.move_wildcard_files(
                        f"{scheduled_scan_dict['result_file_base_name']}*", pending_files_dir, cancelled_files_dir
                    )

                if new_scan_status == "completed":
                    # Move files from "pending" directory to "complete" directory.
                    utility.move_wildcard_files(
                        f"{scheduled_scan_dict['result_file_base_name']}*", pending_files_dir, completed_files_dir
                    )

                    # Django compliant pre-formated datetimestamp.
                    now_datetime = get_current_time()
                    ScheduledScan.objects.filter(scan_engine=request.user).filter(pk=pk).update(
                        completed_time=now_datetime
                    )

                # Update the scheduled_scan_dict with the most recent scan_status state from the PATCH request.  When
                # originally querying above, the old state would passed to utility.py since it hasn't officially been
                # updated by Django's .update() yet.
                scheduled_scan_dict["scan_status"] = new_scan_status

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
        Engine.objects.filter(scan_engine=user).update(last_checkin=now_datetime)

        # Don't filter results for super users.
        if user.is_superuser:
            queryset = ScheduledScan.objects.all()

        # Filter results based off user, "Pending" scan status, and start_datetime for HTTP GET requests.
        elif http_method == "GET":
            queryset = (
                ScheduledScan.objects.filter(scan_engine=user)
                .filter(scan_status__in=["pending", "pause", "cancel"])
                .filter(start_datetime__lt=now_datetime)
            )

        # Allow engines to update scan information.
        elif http_method in ("PATCH"):
            queryset = ScheduledScan.objects.filter(scan_engine=user)

        # Return empty queryset.
        else:
            queryset = []

        return queryset
