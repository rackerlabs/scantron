#!/usr/bin/env python

# Standard Python libraries.
import datetime
import logging

# Third party Python libraries.

# Custom Python libraries.
import django_connector


# Setup logging.
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ROOT_LOGGER = logging.getLogger()


def get_timestamp():
    """Returns formated timestamp."""

    now = datetime.datetime.now()
    timestamp = datetime.datetime.strftime(now, "%Y%m%d_%H%M%S")
    return timestamp


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
    # Return the current local date and time: datetime.datetime(2018, 2, 27, 12, 31, 40, 554840)
    # https://docs.python.org/3.5/library/datetime.html#datetime.datetime.now
    now_datetime = datetime.datetime.now()  # + datetime.timedelta(hours=24)

    # Retrieve all scans.
    scans = django_connector.Scan.objects.all()  # TODO filter based off start time < now_datetime

    if not scans:
        ROOT_LOGGER.debug("No scans exist")
        return

    ROOT_LOGGER.debug(f"Found {len(scans)} scans.")

    # Loop through each scan and extract any recurrences for today.
    for scan in scans:

        # Populate variables from existing database relationships.
        site_name = scan.site.site_name
        scan_agent = scan.site.scan_agent.scan_agent
        scan_binary = scan.site.nmap_command.scan_binary
        nmap_command = scan.site.nmap_command.nmap_command
        targets_file = scan.site.targets_file

        # ROOT_LOGGER.debug(f"Found scan: {site_name}, {targets_file}, {nmap_command}, {scan_agent}, {scan_binary}")

        # Retrieve scan occurences.
        scan_occurence = scan.recurrences.before(now_datetime, dtstart=now_datetime, inc=False)
        if not scan_occurence:
            continue

        # Build start_time.
        start_time = datetime.datetime.combine(scan_occurence.date(), scan.start_time)

        # Convert start_time datetime object to string for result_file_base_name.
        timestamp = datetime.datetime.strftime(start_time, "%Y%m%d_%H%M")

        # Build results file.  "__" is used by master/nmap_results/nmap_to_csv.py to .split() site_name and scan_agent.
        result_file_base_name = f"{clean_text(site_name)}__{clean_text(scan_agent)}__{timestamp}"

        try:
            # Add entry to ScheduledScan model.
            obj, created = django_connector.ScheduledScan.objects.get_or_create(
                site_name=site_name,
                scan_agent=scan_agent,
                start_time=start_time,
                scan_binary=scan_binary,
                nmap_command=nmap_command,
                targets_file=targets_file,
                result_file_base_name=result_file_base_name,
            )

            if created:
                ROOT_LOGGER.debug(
                    f"Adding to scheduled scans: {site_name}, {scan_agent}, {scan_occurence.date()}, {start_time}, {scan_binary}, {nmap_command}, {targets_file}, {result_file_base_name}"
                )

        except Exception as e:
            ROOT_LOGGER.error("Error with site name: {site_name}.  Exception: {e}")


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
