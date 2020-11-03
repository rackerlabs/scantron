from django.db import models
from django.conf import settings
from django.contrib.auth.models import User  # noqa
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, RegexValidator
from django.db.models.signals import post_save
from django.dispatch import receiver

from recurrence.fields import RecurrenceField
from rest_framework.authtoken.models import Token

import extract_targets
import email_validation_utils


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """Automatically generate an API key when a user is created, then create Engine."""

    if created:
        # Generate API token for user.
        api_token = Token.objects.create(user=instance)

        # Only create engine using username and API token for non-admin users.
        if instance.is_superuser is False:
            Engine.objects.create(scan_engine=instance, api_token=api_token)


class Engine(models.Model):
    """Model for an Engine"""

    id = models.AutoField(primary_key=True, verbose_name="Engine ID")
    scan_engine = models.CharField(
        unique=True,
        max_length=255,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/()_\- ]*$",  # Must escape -
                message="Engine name can only contain alphanumeric characters, /, (), -, _, or spaces",
            )
        ],
        verbose_name="Engine Name",
    )
    description = models.CharField(unique=False, max_length=255, blank=True, verbose_name="Engine Description")
    api_token = models.CharField(unique=True, max_length=40, blank=False, verbose_name="API Key")
    last_checkin = models.DateTimeField(blank=True, null=True, verbose_name="Last Engine Check In")

    def __str__(self):
        return str(self.scan_engine)

    class Meta:
        verbose_name_plural = "Engines"


class EnginePool(models.Model):
    """Model for an Engine Pool"""

    id = models.AutoField(primary_key=True, verbose_name="Engine Pool ID")
    engine_pool_name = models.CharField(unique=True, max_length=255, verbose_name="Engine Pool Name")
    scan_engines = models.ManyToManyField(Engine, verbose_name="Scan engines in pool",)

    def __str__(self):
        return str(self.engine_pool_name)

    class Meta:
        verbose_name_plural = "Engine Pools"


class GloballyExcludedTarget(models.Model):
    """Model for globally excluded targets."""

    id = models.AutoField(primary_key=True, verbose_name="Globally excluded target ID")
    # See the client_max_body_size setting in
    # ansible-playbooks/roles/console/templates/etc/nginx/sites-available/scantron_nginx.conf.j2 if the max_length value
    # is changed.
    globally_excluded_targets = models.CharField(
        unique=False,
        max_length=4194304,  # 2^22 = 4194304.  See note above if this value is changed.
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/\.\:\- ]*$",  # Characters to support IPv4, IPv6, and FQDNs only.  Space delimited.
                message="Targets can only contain alphanumeric characters, /, ., :, -, and spaces",
            )
        ],
        verbose_name="Globally Excluded Targets",
    )
    note = models.TextField(unique=False, blank=True, verbose_name="Note")
    last_updated = models.DateTimeField(auto_now=True, verbose_name="Last updated")

    def clean(self):
        """Checks for any invalid IPs, IP subnets, or FQDNs in the globally_excluded_targets field."""

        # Globally excluded targets.
        target_extractor = extract_targets.TargetExtractor(
            targets_string=self.globally_excluded_targets, private_ips_allowed=True, sort_targets=True
        )
        targets_dict = target_extractor.targets_dict

        if targets_dict["invalid_targets"]:
            invalid_targets = ",".join(target_extractor.targets_dict["invalid_targets"])
            raise ValidationError(f"Invalid globally excluded targets provided: {invalid_targets}")

        self.globally_excluded_targets = targets_dict["as_nmap"]

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Globally Excluded Targets"


class ScanCommand(models.Model):
    """Model for a scan command"""

    # fmt: off
    SCAN_BINARY = (
        ("masscan", "masscan"),
        ("nmap", "nmap"),
    )
    # fmt: on

    id = models.AutoField(primary_key=True, verbose_name="scan command ID")
    scan_binary = models.CharField(max_length=7, choices=SCAN_BINARY, default="nmap", verbose_name="Scan binary")
    scan_command_name = models.CharField(unique=True, max_length=255, verbose_name="Scan command name")
    scan_command = models.TextField(unique=False, verbose_name="Scan command")

    def __str__(self):
        return f"{self.scan_binary}||{self.scan_command_name}"

    class Meta:
        verbose_name_plural = "Scan Commands"


class Site(models.Model):
    """Model for a Site.  Must be defined prior to Scan model."""

    id = models.AutoField(primary_key=True, verbose_name="Site ID")
    site_name = models.CharField(
        unique=True,
        max_length=255,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/()_\- ]*$",  # Must escape -
                message="Site name can only contain alphanumeric characters, /, (), -, _, or spaces",
            )
        ],
        verbose_name="Site Name",
    )
    description = models.CharField(unique=False, max_length=255, blank=True, verbose_name="Description")
    # See the client_max_body_size setting in
    # ansible-playbooks/roles/console/templates/etc/nginx/sites-available/scantron_nginx.conf.j2 if the max_length value
    # is changed.
    targets = models.CharField(
        unique=False,
        max_length=4194304,  # 2^22 = 4194304.  See note above if this value is changed.
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/\.\:\- ]*$",  # Characters to support IPv4, IPv6, and FQDNs only.  Space delimited.
                message="Targets can only contain alphanumeric characters, /, ., :, -, and spaces",
            )
        ],
        verbose_name="Targets",
    )
    # See the client_max_body_size setting in
    # ansible-playbooks/roles/console/templates/etc/nginx/sites-available/scantron_nginx.conf.j2 if the max_length value
    # is changed.
    excluded_targets = models.CharField(
        unique=False,
        blank=True,
        max_length=4194304,  # 2^22 = 4194304.  See note above if this value is changed.
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/\.\:\- ]*$",  # Characters to support IPv4, IPv6, and FQDNs only.  Space delimited.
                message="Excluded targets can only contain alphanumeric characters, /, ., :, -, and spaces",
            )
        ],
        verbose_name="Excluded targets",
    )
    scan_command = models.ForeignKey(ScanCommand, on_delete=models.CASCADE, verbose_name="Scan binary and name")
    scan_engine = models.ForeignKey(Engine, blank=True, null=True, on_delete=models.CASCADE, verbose_name="Scan Engine")
    scan_engine_pool = models.ForeignKey(
        EnginePool, blank=True, null=True, on_delete=models.CASCADE, verbose_name="Scan Engine Pool"
    )
    email_scan_alerts = models.BooleanField(verbose_name="Email scan alerts?")
    email_alert_addresses = models.CharField(
        unique=False, blank=True, max_length=4096, verbose_name="Email alert addresses, comma separated"
    )

    def clean(self):
        """Checks for any invalid IPs, IP subnets, or FQDNs in the targets and excluded_targets fields."""

        # Ensure only 1 scan engine / scan engine pool is selected.
        if self.scan_engine and self.scan_engine_pool:
            raise ValidationError("Only select a single scan engine or scan engine pool.")

        # Ensure a scan engine or scan engine pool is selected.  Can't enforce within models.ForeignKey using
        # blank=False and null=False, because they could be blank/empty if the other scan engine or scan engine pool is
        # selected.
        if not self.scan_engine and not self.scan_engine_pool:
            raise ValidationError("Select a single scan engine or scan engine pool.")

        # Targets
        target_extractor = extract_targets.TargetExtractor(
            targets_string=self.targets, private_ips_allowed=True, sort_targets=True
        )
        targets_dict = target_extractor.targets_dict

        if targets_dict["invalid_targets"]:
            invalid_targets = ",".join(target_extractor.targets_dict["invalid_targets"])
            raise ValidationError(f"Invalid targets provided: {invalid_targets}")

        self.targets = targets_dict["as_nmap"]

        # Excluded targets
        target_extractor = extract_targets.TargetExtractor(
            targets_string=self.excluded_targets, private_ips_allowed=True, sort_targets=True
        )
        targets_dict = target_extractor.targets_dict

        if targets_dict["invalid_targets"]:
            invalid_targets = ",".join(target_extractor.targets_dict["invalid_targets"])
            raise ValidationError(f"Invalid excluded targets provided: {invalid_targets}")

        self.excluded_targets = targets_dict["as_nmap"]

        # Email scan alerts and email addresses.
        if self.email_scan_alerts and not self.email_alert_addresses:
            raise ValidationError(f"Provide an email address if enabling 'Email scan alerts'")

        # Check for valid email addresseses string.
        if self.email_alert_addresses:
            """Checks that email addresses are valid and returns a cleaned up string of them to save to the database."""
            self.email_alert_addresses = email_validation_utils.validate_string_of_email_addresses(
                self.email_alert_addresses
            )

    def __str__(self):
        return str(self.site_name)

    class Meta:
        verbose_name_plural = "Sites"
        ordering = ["site_name"]


class Scan(models.Model):
    """Model for a type of Scan."""

    id = models.AutoField(primary_key=True, verbose_name="Scan ID")
    site = models.ForeignKey(Site, on_delete=models.CASCADE, verbose_name="Site ID")
    scan_name = models.CharField(unique=False, max_length=255, blank=True, verbose_name="Scan Name")
    enable_scan = models.BooleanField(verbose_name="Enable scan?")
    start_time = models.TimeField(verbose_name="Scan start time")
    recurrences = RecurrenceField(include_dtstart=False, verbose_name="Recurrences")

    def __str__(self):
        return str(self.id)

    # def get_text_rules_inclusion(self):
    #     schedule_scan = ScheduledScan.objects.get(id=self.id)
    #     text_rules_inclusion = []
    #
    #     for rule in schedule_scan.recurrences.rrules:
    #         text_rules_inclusion.append(rule.to_text())
    #
    #     print(text_rules_inclusion)
    #     return text_rules_inclusion

    class Meta:
        verbose_name_plural = "Scans"


class ScheduledScan(models.Model):
    """Model for a list of upcoming scans for a day."""

    SCAN_STATUS_CHOICES = (
        ("pending", "Pending"),
        ("started", "Started"),
        ("pause", "Pause"),
        ("paused", "Paused"),
        ("cancel", "Cancel"),
        ("cancelled", "Cancelled"),
        ("completed", "Completed"),
        ("error", "Error"),
    )

    id = models.AutoField(primary_key=True, verbose_name="Scheduled Scan ID")
    site_name = models.CharField(
        unique=False,
        max_length=255,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/()_\- ]*$",  # Must escape -
                message="Site name can only contain alphanumeric characters, /, (), -, _, or spaces",
            )
        ],
        verbose_name="Site Name",
    )
    start_time = models.TimeField(verbose_name="Scan start time")
    scan_engine = models.CharField(
        unique=False,
        max_length=255,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/()_\- ]*$",  # Must escape -
                message="Engine name can only contain alphanumeric characters, /, (), -, _, or spaces",
            )
        ],
        verbose_name="Engine Name",
    )
    start_datetime = models.DateTimeField(verbose_name="Scheduled scan start date and time")
    scan_binary = models.CharField(max_length=7, default="nmap", verbose_name="Scan binary")
    scan_command = models.TextField(unique=False, verbose_name="Scan command")
    # See the client_max_body_size setting in
    # ansible-playbooks/roles/console/templates/etc/nginx/sites-available/scantron_nginx.conf.j2 if the max_length value
    # is changed.
    targets = models.CharField(
        unique=False,
        max_length=4194304,  # 2^22 = 4194304.  See note above if this value is changed.
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/\.\: ]*$",  # Characters to support IPv4, IPv6, and FQDNs only.  Space delimited.
                message="Targets can only contain alphanumeric characters, /, ., :, and spaces",
            )
        ],
        verbose_name="Targets",
    )
    # See the client_max_body_size setting in
    # ansible-playbooks/roles/console/templates/etc/nginx/sites-available/scantron_nginx.conf.j2 if the max_length value
    # is changed.
    excluded_targets = models.CharField(
        unique=False,
        blank=True,
        max_length=4194304,  # 2^22 = 4194304.  See note above if this value is changed.
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9/\.\: ]*$",  # Characters to support IPv4, IPv6, and FQDNs only.  Space delimited.
                message="Excluded targets can only contain alphanumeric characters, /, ., :, and spaces",
            )
        ],
        verbose_name="Excluded targets",
    )
    scan_status = models.CharField(
        max_length=9, choices=SCAN_STATUS_CHOICES, default="pending", verbose_name="Scan status"
    )
    completed_time = models.DateTimeField(null=True, blank=True, verbose_name="Scan completion time")
    result_file_base_name = models.CharField(max_length=255, blank=False, verbose_name="Result file base name")
    pooled_scan_result_file_base_name = models.CharField(
        max_length=255, blank=True, verbose_name="Pooled scan result file base name"
    )
    scan_binary_process_id = models.IntegerField(
        validators=[MinValueValidator(limit_value=0, message="Process ID must be a positive integer")],
        verbose_name="Scan binary process ID.",
    )

    def clean(self):
        """Based off the current scan status, ensure the updated scan status is valid."""

        # Any updates to this dictionary should also be updated in console/django_scantron/api/views.py
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

        scheduled_scan_dict = ScheduledScan.objects.get(pk=self.pk)
        current_scan_status = scheduled_scan_dict.scan_status

        if self.scan_status not in scan_status_allowed_state_update_dict[current_scan_status]:
            # Convert list to a string.
            valid_scan_states = ", ".join(scan_status_allowed_state_update_dict[current_scan_status])

            raise ValidationError(
                f"Invalid scan status change requested.  Scan status state '{current_scan_status}' can only transition "
                f"to: {valid_scan_states}"
            )

        # If a scan is paused and needs to be cancelled, don't set the state to "cancel", because the engine will try and
        # cancel a running process that doesn't exist and error out.  Just bypass the "cancel" state and set it to
        # "cancelled".  This logic is not needed on the client / API side in the ScheduledScanViewSet class in
        # console/django_scantron/api/views.py.
        if current_scan_status == "paused" and self.scan_status == "cancel":
            self.scan_status = "cancelled"

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Scheduled Scans"
