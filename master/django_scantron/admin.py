from django.contrib import admin
from . import models


class AgentAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_agent", "description", "api_token", "last_checkin")

    readonly_fields = ("id", "scan_agent", "api_token")


class ScanCommandAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_binary", "scan_command_name", "scan_command")


class ScanAdmin(admin.ModelAdmin):

    list_display = ("id", "site", "scan_name", "start_time", "recurrences")

    exclude = ("completed_time", "result_file_base_name")


class SiteAdmin(admin.ModelAdmin):
    list_display = ("id", "site_name", "description", "targets", "scan_command", "scan_agent")


class ScheduledScanAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "site_name",
        "site_name_id",
        "scan_id",
        "scan_agent",
        "scan_agent_id",
        "start_datetime",
        "scan_binary",
        "scan_command",
        "scan_command_id",
        "targets",
        "scan_status",
        "completed_time",
        "result_file_base_name",
    )

    exclude = ("completed_time", "result_file_base_name")


def _register(model, admin_class):
    admin.site.register(model, admin_class)


_register(models.Agent, AgentAdmin)
_register(models.ScanCommand, ScanCommandAdmin)
_register(models.Scan, ScanAdmin)
_register(models.ScheduledScan, ScheduledScanAdmin)
_register(models.Site, SiteAdmin)
