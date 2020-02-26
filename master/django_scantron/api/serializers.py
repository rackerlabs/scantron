from rest_framework import serializers

from django_scantron.models import (
    Agent,
    ScanCommand,
    Scan,
    ScheduledScan,
    Site,
)

import extract_targets

# Serializers define the API representations.


class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = ("id", "scan_agent", "description", "api_token", "last_checkin")


class ScanCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanCommand
        fields = (
            "id",
            "scan_binary",
            "scan_command_name",
            "scan_command",
        )


class SiteSerializer(serializers.ModelSerializer):
    # Separate validation needed for DRF; doesn't use model's clean() function anymore.
    # https://www.django-rest-framework.org/community/3.0-announcement/#differences-between-modelserializer-validation-and-modelform

    def validate(self, attrs):
        """Checks for any invalid IPs, IP subnets, or FQDNs in the targets or excluded_targets fields."""

        # Targets
        if "targets" in attrs:
            targets = attrs["targets"]

            target_extractor = extract_targets.TargetExtractor(
                targets_string=targets, private_ips_allowed=True, sort_targets=True
            )
            targets_dict = target_extractor.targets_dict

            if targets_dict["invalid_targets"]:
                invalid_targets = ",".join(targets_dict["invalid_targets"])
                raise serializers.ValidationError(f"Invalid targets provided: {invalid_targets}")

        # Excluded targets
        if "excluded_targets" in attrs:
            excluded_targets = attrs["excluded_targets"]

            target_extractor = extract_targets.TargetExtractor(
                targets_string=excluded_targets, private_ips_allowed=True, sort_targets=True
            )
            targets_dict = target_extractor.targets_dict

            if targets_dict["invalid_targets"]:
                invalid_targets = ",".join(targets_dict["invalid_targets"])
                raise serializers.ValidationError(f"Invalid excluded targets provided: {invalid_targets}")

        # Email scan alerts and email address.
        if ("email_scan_alerts" in attrs) and ("email_alert_address" in attrs):

            email_scan_alerts = attrs["email_scan_alerts"]
            email_alert_address = attrs["email_alert_address"]

            if email_scan_alerts and not email_alert_address:
                raise serializers.ValidationError(f"Provide an email address if enabling 'Email scan alerts'")

        return attrs

    class Meta:
        model = Site
        fields = (
            "id",
            "site_name",
            "description",
            "targets",
            "excluded_targets",
            "scan_command",
            "scan_agent",
            "email_scan_alerts",
            "email_alert_address",
        )


class ScanSerializer(serializers.ModelSerializer):
    # nested relationship
    # http://www.django-rest-framework.org/api-guide/relations/#nested-relationships
    # site = SiteSerializer(many=False)

    class Meta:
        model = Scan
        fields = (
            "id",
            "site",
            "scan_name",
            "start_time",
            "recurrences",
        )


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledScan
        fields = (
            "id",
            "site_name",
            "scan_agent",
            "start_datetime",
            "scan_binary",
            "scan_command",
            "targets",
            "excluded_targets",
            "scan_status",
            "completed_time",
            "result_file_base_name",
        )
