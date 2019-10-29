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

    # Retrieve all scans.
    scans = django_connector.Scan.objects.all()

    if not scans:
        ROOT_LOGGER.debug("No scans exist")
        return

    ROOT_LOGGER.debug(f"Found {len(scans)} scans.")

    # Loop through each scan and extract any recurrences for today.
    for scan in scans:

        # Convoluted way of determining if a scan occurrence is today.
        # Have fun understanding the documentation for django-recurrence.
        # https://django-recurrence.readthedocs.io/en/latest/usage/recurrence_field.html#getting-occurrences-between-two-dates
        # https://github.com/django-recurrence/django-recurrence/issues/50
        now_datetime = datetime.datetime.now()
        # now_datetime += datetime.timedelta(days=7)  # For testing.
        beginning_of_today = now_datetime.replace(hour=0).replace(minute=0).replace(second=0).replace(microsecond=0)
        end_of_today = now_datetime.replace(hour=23).replace(minute=59).replace(second=59).replace(microsecond=0)
        scan_occurence = scan.recurrences.between(beginning_of_today, end_of_today, inc=True)

        # If a scan is not supposed to occur today, then bail, otherwise extract the datetime.
        if not scan_occurence:
            continue
        else:
            scan_occurence = scan_occurence[0]

        # A scan is supposed to occur today, populate the remaining variables from existing database relationships.
        site_name = scan.site.site_name
        site_name_id = scan.site.id
        scan_agent = scan.site.scan_agent.scan_agent
        scan_agent_id = scan.site.scan_agent_id
        scan_binary = scan.site.nmap_command.scan_binary
        nmap_command = scan.site.nmap_command.nmap_command
        nmap_command_id = scan.site.nmap_command.id
        targets = scan.site.targets

        # Build start_datetime based off Django's TIME_ZONE setting.
        # https://www.saltycrane.com/blog/2009/05/converting-time-zones-datetime-objects-python/#add-timezone-localize
        start_datetime_tz_naive = datetime.datetime.combine(scan_occurence.date(), scan.start_time)
        start_datetime = pytz.timezone(settings.TIME_ZONE).localize(start_datetime_tz_naive)

        # Check and see if a scan has been scheduled for today's date and start time.  Utilize *_id so that the
        # human-readable names can be changed without triggering a new scan.  The site_name_id, scan_agent_id, and
        # nmap_command_id, are not exposed in the ScheduledScan (agent's) API endpoint.
        scan_object = (
            django_connector.ScheduledScan.objects.filter(start_datetime=start_datetime)
            .filter(site_name_id=site_name_id)
            .filter(scan_agent_id=scan_agent_id)
            .filter(nmap_command_id=nmap_command_id)
        )

        # Scan has already been created, let's bail.
        if scan_object:
            continue

        # Convert start_datetime datetime object to string for result_file_base_name.
        timestamp = datetime.datetime.strftime(start_datetime, "%Y%m%d_%H%M")

        # Build results file.  "__" is used by master/nmap_results/nmap_to_csv.py to .split() site_name and scan_agent.
        result_file_base_name = f"{clean_text(site_name)}__{clean_text(scan_agent)}__{timestamp}"

        try:
            # Add entry to ScheduledScan model.
            obj, created = django_connector.ScheduledScan.objects.get_or_create(
                site_name=site_name,
                site_name_id=site_name_id,
                scan_agent=scan_agent,
                scan_agent_id=scan_agent_id,
                start_datetime=start_datetime,
                scan_binary=scan_binary,
                nmap_command=nmap_command,
                nmap_command_id=nmap_command_id,
                targets=targets,
                result_file_base_name=result_file_base_name,
                scan_status="pending",
            )

            if created:
                ROOT_LOGGER.debug(
                    f"Adding to scheduled scans: {site_name}, {scan_agent}, {scan_occurence.date()}, {start_datetime},"
                    f"{scan_binary}, {nmap_command}, {result_file_base_name}"
                )

        except Exception as e:
            ROOT_LOGGER.error(f"Error with site name: {site_name}.  Exception: {e}")


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

    ROOT_LOGGER.debug("Done!")
