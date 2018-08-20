from rest_framework import serializers
from django_scantron.models import Agent, NmapCommand, Scan, ScheduledScan, Site


# Serializers define the API representations.

class AgentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Agent
        fields = (
            'scan_agent',
            'description',
            'api_token',
        )  # Must have trailing ','


class NmapCommandSerializer(serializers.ModelSerializer):

    class Meta:
        model = NmapCommand
        fields = (
            'nmap_scan_name',
            'nmap_command',
        )  # Must have trailing ','


class SiteSerializer(serializers.ModelSerializer):
    nmap_command = serializers.StringRelatedField(many=False)
    scan_agent = serializers.StringRelatedField(many=False)

    class Meta:
        model = Site
        fields = (
            'id',
            'site_name',
            'description',
            'targets_file',
            'nmap_command',
            'scan_agent',
        )  # Must have trailing ','


class ScanGETSerializer(serializers.ModelSerializer):
    # nested relationship
    # http://www.django-rest-framework.org/api-guide/relations/#nested-relationships
    site = SiteSerializer(many=False)

    class Meta:
        model = Scan
        fields = (
            'id',
            'site',
            'scan_name',
            'start_time',
        )  # Must have trailing ','


class ScanPOSTSerializer(serializers.ModelSerializer):

    class Meta:
        model = Scan
        fields = (
            'id',
            'site',
            'scan_name',
            'start_time',
            # 'recurrences',
        )  # Must have trailing ','


class ScheduledScanSerializer(serializers.ModelSerializer):

    class Meta:
        model = ScheduledScan
        fields = (
            'id',
            'site_name',
            'scan_agent',
            'start_time',
            'nmap_command',
            'targets_file',
            'scan_status',
            'completed_time',
            'result_file_base_name',
        )  # Must have trailing ','
