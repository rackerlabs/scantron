from django.contrib import admin
from . import models


class AgentAdmin(admin.ModelAdmin):

    list_display = (
        'id',
        'scan_agent',
        'description',
        'api_token',
        'last_checkin',
    )

    readonly_fields = (
        'id',
        'scan_agent',
        'api_token'
    )


class NmapCommandAdmin(admin.ModelAdmin):

    list_display = (
        'id',
        'scan_binary',
        'nmap_scan_name',
        'nmap_command',
    )


class SiteAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'site_name',
        'description',
        'targets_file',
        'nmap_command',
        'scan_agent',
    )


class ScanAdmin(admin.ModelAdmin):

    list_display = (
        'id',
        'site',
        'scan_name',
        'start_time',
        'recurrences',
    )

    exclude = (
        'completed_time',
        'result_file_base_name',
    )


class ScheduledScanAdmin(admin.ModelAdmin):

    list_display = (
        'id',
        'site_name',
        'scan_agent',
        'start_time',
        'scan_binary',
        'nmap_command',
        'targets_file',
        'scan_status',
        'completed_time',
        'result_file_base_name',
    )

    exclude = (
        'completed_time',
        'result_file_base_name',
    )


def _register(model, admin_class):
    admin.site.register(model, admin_class)


_register(models.Agent, AgentAdmin)
_register(models.NmapCommand, NmapCommandAdmin)
_register(models.Scan, ScanAdmin)
_register(models.ScheduledScan, ScheduledScanAdmin)
_register(models.Site, SiteAdmin)
