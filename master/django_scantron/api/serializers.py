from rest_framework import serializers

# fmt: off
from django_scantron.models import (
    Agent,
    NmapCommand,
    Scan,
    ScheduledScan,
    Site,
    TargetFile,
)

# Serializers define the API representations.


class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = ("scan_agent", "description", "api_token",)


class NmapCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = NmapCommand
        fields = ("scan_binary", "nmap_scan_name", "nmap_command",)


class TargetFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetFile
        fields = ("target_file_name",)


class SiteSerializer(serializers.ModelSerializer):
    nmap_command = serializers.StringRelatedField(many=False)
    scan_agent = serializers.StringRelatedField(many=False)

    class Meta:
        model = Site
        fields = (
            "id",
            "site_name",
            "description",
            "target_file",
            "nmap_command",
            "scan_agent",
        )


class ScanSerializer(serializers.ModelSerializer):
    # nested relationship
    # http://www.django-rest-framework.org/api-guide/relations/#nested-relationships
    site = SiteSerializer(many=False)

    class Meta:
        model = Scan
        fields = ("id", "site", "scan_name", "start_time",)


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledScan
        fields = (
            "id",
            "site_name",
            "scan_agent",
            "start_time",
            "scan_binary",
            "nmap_command",
            "target_file",
            "scan_status",
            "completed_time",
            "result_file_base_name",
        )

# fmt: on
