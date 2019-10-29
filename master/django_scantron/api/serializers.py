from rest_framework import serializers

# fmt: off
from django_scantron.models import (
    Agent,
    NmapCommand,
    Scan,
    ScheduledScan,
    Site,
)

import extract_ips

# Serializers define the API representations.


class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = ("scan_agent", "description", "api_token",)


class NmapCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = NmapCommand
        fields = ("scan_binary", "nmap_scan_name", "nmap_command",)


class SiteSerializer(serializers.ModelSerializer):
    nmap_command = serializers.StringRelatedField(many=False)
    scan_agent = serializers.StringRelatedField(many=False)

    # Separate validation need for DRF; doesn't use model's clean() function anymore.
    # https://www.django-rest-framework.org/community/3.0-announcement/#differences-between-modelserializer-validation-and-modelform
    def validate(self, attrs):
        """Checks for any invalid IPs, IP subnets, or FQDNs in targets field."""

        targets = attrs["targets"]

        target_extractor = extract_ips.TargetExtractor(targets_string=targets, private_ips_allowed=True)
        targets_dict = target_extractor.targets_dict

        if targets_dict["invalid_targets"]:
            invalid_targets = ",".join(targets_dict["invalid_targets"])
            raise serializers.ValidationError(f"Invalid targets provided: {invalid_targets}")

        return attrs

    class Meta:
        model = Site
        fields = (
            "id",
            "site_name",
            "description",
            "targets",
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
            "start_datetime",
            "scan_binary",
            "nmap_command",
            "targets",
            "scan_status",
            "completed_time",
            "result_file_base_name",
        )

# fmt: on
