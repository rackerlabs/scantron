#!/usr/bin/env python

# Standard Python libraries.
import datetime
import logging
import pytz

# Third party Python libraries.
from django.conf import settings

# Custom Python libraries.
import django_connector


# Setup logging.
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ROOT_LOGGER = logging.getLogger()


def clean_text(uncleaned_text):
    """Clean text by replacing specific characters."""

    cleaned_text = (
        uncleaned_text.lower()
        .replace(" - ", "_")
        .replace("-", "_")
        .replace(" ", "_")
        .replace("__", "_")
        .replace("/", "_")
    )

    return cleaned_text


def main():

    # Determine time variables to assist in filtering.
    now_datetime = datetime.datetime.now()
    now_time = now_datetime.time()
    now_time_hour = now_time.hour
    now_time_minute = now_time.minute

    # Only filter on scans that should start at this time based off hour and minute, ignoring seconds.
    # If minute is the time resolution, this script (wrapped with scan_scheduler.sh) must be executed every minute
    # through cron.  We can't filter on occurrences using Django's filter() method; it will have to be checked using
    # logic below.
    scans = django_connector.Scan.objects.filter(start_time__hour=now_time_hour).filter(
        start_time__minute=now_time_minute
    )

    if not scans:
        ROOT_LOGGER.info(f"No scans scheduled to start at this time: {now_time:%H}:{now_time:%M}.")
        return

    ROOT_LOGGER.info(f"Found {len(scans)} scans scheduled to start at {now_time:%H}:{now_time:%M}.")

    # Loop through each scan that is scheduled to start at this time.
    for scan in scans:

        # Convoluted way of determining if a scan occurrence is today.
        # Have fun understanding the documentation for django-recurrence.
        # https://django-recurrence.readthedocs.io/en/latest/usage/recurrence_field.html#getting-occurrences-between-two-dates
        # https://github.com/django-recurrence/django-recurrence/issues/50
        beginning_of_today = now_datetime.replace(hour=0).replace(minute=0).replace(second=0).replace(microsecond=0)
        end_of_today = now_datetime.replace(hour=23).replace(minute=59).replace(second=59).replace(microsecond=0)
        scan_occurrence = scan.recurrences.between(beginning_of_today, end_of_today, inc=True)

        # If a scan is not supposed to occur today, then bail, otherwise extract the datetime.
        if not scan_occurrence:
            continue
        else:
            scan_occurrence = scan_occurrence[0]
            ROOT_LOGGER.info(f"Found scan_occurrence for today: {scan_occurrence}.")

        # Let's extract the remaining variables from existing database relationships.  Note that the Scan model has the
        # Site model as a foreign key, and in turn, the Site model has foreign keys for the Agent and ScanCommand models
        # (see the scantron_model_graph.png for a visualization).  Therefore, if a field from the Agent or
        # ScanCommand models is updated, it will update the Site model, and cascade to the Scan model.

        # Scan model.
        scan_start_time = scan.start_time

        # Site model.
        site_name = scan.site.site_name
        targets = scan.site.targets
        excluded_targets = scan.site.excluded_targets

        # Agent model.
        scan_agent = scan.site.scan_agent.scan_agent

        # ScanCommand model.
        scan_command = scan.site.scan_command.scan_command
        scan_binary = scan.site.scan_command.scan_binary

        # The ScheduledScan model acts as the sanitized endpoint for agents to determine scan jobs.  We don't want to
        # expose the other models, so we populate that ScheduledScan model instead.  The actual exposed fields for the
        # API are controlled using master/api/serializers.py.

        # start_datetime is a DateTimeField in ScheduledScan, but the Scan model only contains start_time (TimeField)
        # and a recurrence date, so we have to build a DateTimeField equivalent.
        # Build start_datetime based off Django's TIME_ZONE setting.
        # https://www.saltycrane.com/blog/2009/05/converting-time-zones-datetime-objects-python/#add-timezone-localize
        start_datetime_tz_naive = datetime.datetime.combine(scan_occurrence.date(), scan_start_time)
        start_datetime = pytz.timezone(settings.TIME_ZONE).localize(start_datetime_tz_naive)

        # Convert start_datetime datetime object to string for result_file_base_name.
        timestamp = datetime.datetime.strftime(start_datetime, "%Y%m%d_%H%M")

        # Build result_file_base_name file.  "__" is used by master/scan_results/nmap_to_csv.py to .split() site_name
        # and scan_agent.
        result_file_base_name = f"{clean_text(site_name)}__{clean_text(scan_agent)}__{timestamp}"

        scan_dict = {
            "site_name": site_name,
            "start_time": scan_start_time,
            "scan_agent": scan_agent,
            "start_datetime": start_datetime,
            "scan_binary": scan_binary,
            "scan_command": scan_command,
            "targets": targets,
            "excluded_targets": excluded_targets,
            "result_file_base_name": result_file_base_name,
            "scan_status": "pending",
        }

        # Ensure none of the values are empty.  blank=False is only enforced through forms, which this method of
        # creating a scheduled scan does not honor.
        empty_scan_dict_value_detected = False

        for key, value in scan_dict.items():

            # Ignore fields that are allowed to be empty.
            if key in ["excluded_targets"]:
                continue

            if not value:
                ROOT_LOGGER.error(f"scan_dict['{key}'] has an empty value.")
                empty_scan_dict_value_detected = True

        if empty_scan_dict_value_detected:
            continue

        try:
            # Add entry to ScheduledScan model.  Convert dictionary to kwargs using **.
            # https://stackoverflow.com/questions/5710391/converting-python-dict-to-kwargs
            obj, created = django_connector.ScheduledScan.objects.get_or_create(**scan_dict)

            if created:
                ROOT_LOGGER.info(f"Adding to scheduled scans: {scan_dict}")
            else:
                ROOT_LOGGER.error(f"Scheduled scan not created: {scan_dict}")

        except Exception as e:
            ROOT_LOGGER.exception(f"Error adding scan: {scan_dict}.  Exception: {e}")


if __name__ == "__main__":

    ROOT_LOGGER.setLevel(10)  # DEBUG

    # Log file handling.
    file_handler = logging.FileHandler("scan_scheduler.log")
    file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(file_handler)

    # Console logging.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    main()

    ROOT_LOGGER.info("Done!")
