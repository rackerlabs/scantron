from rest_framework import serializers

from django_scantron.models import (
    Engine,
    EnginePool,
    GloballyExcludedTarget,
    ScanCommand,
    Scan,
    ScheduledScan,
    Site,
)

import extract_targets
import email_validation_utils

# Serializers define the API representations.


class EngineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engine
        fields = ("id", "scan_engine", "description", "api_token", "last_checkin")


class EnginePoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnginePool
        fields = ("id", "engine_pool_name", "scan_engines")


class GloballyExcludedTargetSerializer(serializers.ModelSerializer):

    # Separate validation needed for DRF; doesn't use model's clean() function anymore.
    # https://www.django-rest-framework.org/community/3.0-announcement/#differences-between-modelserializer-validation-and-modelform

    def validate(self, attrs):
        """Checks for any invalid IPs, IP subnets, or FQDNs in the globally_excluded_targets field."""

        # Globally excluded targets.
        if "globally_excluded_targets" in attrs:
            globally_excluded_targets = attrs["globally_excluded_targets"]

            target_extractor = extract_targets.TargetExtractor(
                targets_string=globally_excluded_targets, private_ips_allowed=True, sort_targets=True
            )
            targets_dict = target_extractor.targets_dict

            if targets_dict["invalid_targets"]:
                invalid_targets = ",".join(targets_dict["invalid_targets"])
                raise serializers.ValidationError(f"Invalid globally excluded targets provided: {invalid_targets}")

        return attrs

    class Meta:
        model = GloballyExcludedTarget
        fields = ("id", "globally_excluded_targets", "note", "last_updated")


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

        # TODO add scan engine / scan engine pool checks.

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
        if ("email_scan_alerts" in attrs) and ("email_alert_addresses" in attrs):

            email_scan_alerts = attrs["email_scan_alerts"]
            email_alert_addresses = attrs["email_alert_addresses"]

            if email_scan_alerts and not email_alert_addresses:
                raise serializers.ValidationError(f"Provide an email address if enabling 'Email scan alerts'")

        # Check for valid email addresseses string.
        if "email_alert_addresses" in attrs:
            """Checks that email addresses are valid and returns a cleaned up string of them to save to the database."""

            email_alert_addresses = attrs["email_alert_addresses"]
            attrs["email_alert_addresses"] = email_validation_utils.validate_string_of_email_addresses(
                email_alert_addresses
            )

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
            "scan_engine",
            "scan_engine_pool",
            "email_scan_alerts",
            "email_alert_addresses",
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
            "enable_scan",
            "start_time",
            "recurrences",
        )


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledScan
        fields = (
            "id",
            "site_name",
            "scan_engine",
            "start_datetime",
            "scan_binary",
            "scan_command",
            "targets",
            "excluded_targets",
            "scan_status",
            "completed_time",
            "result_file_base_name",
            "scan_binary_process_id",
        )
        read_only_fields = (
            "id",
            "site_name",
            "scan_engine",
            "start_datetime",
            "scan_binary",
            "scan_command",
            "targets",
            "excluded_targets",
            # "scan_status",
            # "completed_time",
            # "result_file_base_name",
            # "scan_binary_process_id",
        )
