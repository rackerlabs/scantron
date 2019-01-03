from django.contrib import admin
from . import models


class AgentAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_agent", "description", "api_token", "last_checkin")

    readonly_fields = ("id", "scan_agent", "api_token")


class NmapCommandAdmin(admin.ModelAdmin):

    list_display = ("id", "scan_binary", "nmap_scan_name", "nmap_command")


class ScanAdmin(admin.ModelAdmin):

    list_display = ("id", "site", "scan_name", "start_time", "recurrences")

    exclude = ("completed_time", "result_file_base_name")


class SiteAdmin(admin.ModelAdmin):
    list_display = ("id", "site_name", "description", "target_file", "nmap_command", "scan_agent")


class ScheduledScanAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "site_name",
        "site_name_id",
        "scan_agent",
        "scan_agent_id",
        "start_time",
        "scan_binary",
        "nmap_command",
        "nmap_command_id",
        "target_file",
        "target_file_id",
        "scan_status",
        "completed_time",
        "result_file_base_name",
    )

    exclude = ("completed_time", "result_file_base_name")


class TargetFileAdmin(admin.ModelAdmin):

    list_display = ("id", "target_file_name")


def _register(model, admin_class):
    admin.site.register(model, admin_class)


_register(models.Agent, AgentAdmin)
_register(models.NmapCommand, NmapCommandAdmin)
_register(models.Scan, ScanAdmin)
_register(models.ScheduledScan, ScheduledScanAdmin)
_register(models.Site, SiteAdmin)
_register(models.TargetFile, TargetFileAdmin)
