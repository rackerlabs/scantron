from django.contrib import admin

# from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from . import models


# Taken from django-all-auth: https://django-allauth.readthedocs.io/en/latest/advanced.html#admin
# "require users to login before going to the Django admin site’s login page"
# admin.site.login = login_required(admin.site.login)


# View sessions in Django Admin.
class SessionAdmin(admin.ModelAdmin):
    def _session_data(self, obj):
        return obj.get_decoded()

    list_display = ["session_key", "_session_data", "expire_date"]


class ConfigurationAdmin(admin.ModelAdmin):

    list_display = ("id", "enable_scan_retention", "scan_retention_in_days", "created", "last_updated")


class EngineAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_engine", "description", "api_token", "last_checkin", "created", "last_updated")
    readonly_fields = ("id", "scan_engine", "api_token", "last_checkin")


class EnginePoolAdmin(admin.ModelAdmin):

    list_display = ("id", "engine_pool_name", "created", "last_updated")


class GloballyExcludedTargetAdmin(admin.ModelAdmin):

    list_display = ("id", "globally_excluded_targets", "note", "created", "last_updated")


class ScanCommandAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_binary", "scan_command_name", "scan_command", "created", "last_updated")
    list_filter = ("scan_binary",)


class ScanAdmin(admin.ModelAdmin):

    list_display = ("id", "site", "scan_name", "enable_scan", "start_time", "recurrences", "created", "last_updated")
    list_filter = ("enable_scan",)
    exclude = ("completed_time", "result_file_base_name", "dtstart")


class SiteAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "site_name",
        "description",
        "targets",
        "excluded_targets",
        "scan_command",
        "scan_engine",
        "scan_engine_pool",
        "email_scan_alerts",
        "email_alert_addresses",
        "email_scan_diff",
        "email_scan_diff_addresses",
        "created",
        "last_updated",
    )


class ScheduledScanAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "site_name",
        "start_time",
        "scan_engine",
        "start_datetime",
        "scan_binary",
        "scan_command",
        "targets",
        "excluded_targets",
        "scan_status",
        "completed_time",
        "result_file_base_name",
        "pooled_scan_result_file_base_name",
        "scan_binary_process_id",
    )
    list_filter = ("scan_engine", "scan_binary", "scan_status")
    exclude = ("completed_time", "result_file_base_name")


def _register(model, admin_class):
    admin.site.register(model, admin_class)


_register(Session, SessionAdmin)

_register(models.Configuration, ConfigurationAdmin)
_register(models.Engine, EngineAdmin)
_register(models.EnginePool, EnginePoolAdmin)
_register(models.GloballyExcludedTarget, GloballyExcludedTargetAdmin)
_register(models.ScanCommand, ScanCommandAdmin)
_register(models.Scan, ScanAdmin)
_register(models.ScheduledScan, ScheduledScanAdmin)
_register(models.Site, SiteAdmin)
