#!/usr/bin/env python
import datetime

import django_connector


def get_timestamp():
    """Returns formated timestamp.
    """

    now = datetime.datetime.now()
    timestamp = datetime.datetime.strftime(now, "%Y%m%d_%H%M%S")
    return timestamp


def clean_text(uncleaned_text):
    """Clean text by replacing specific characters.
    """

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
    now_datetime = datetime.datetime.now()

    # Retrieve all scans.
    scans = (
        django_connector.Scan.objects.all()
    )  # TODO filter based off start time < now_datetime

    if not scans:
        print("[-] No scans exist")
        return

    # Loop through each scan and extract any recurrences for today.
    for scan in scans:
        scan_occurence = scan.recurrences.before(
            now_datetime, dtstart=now_datetime, inc=False
        )
        if not scan_occurence:
            continue

        # Build start_time
        start_time = datetime.datetime.combine(scan_occurence.date(), scan.start_time)

        # Populate variables from existing database relationships.
        site_name = scan.site.site_name
        scan_agent = scan.site.scan_agent.scan_agent
        nmap_command = scan.site.nmap_command.nmap_command
        targets_file = scan.site.targets_file

        # Convert start_time datetime object to string for result_file_base_name.
        timestamp = datetime.datetime.strftime(start_time, "%Y%m%d_%H%M")

        # Build results file.
        result_file_base_name = "{}_{}_{}".format(
            clean_text(site_name), clean_text(scan_agent), timestamp
        )

        print("[+] Adding:")
        print(
            "\t{}, {}, {}, {}, {}, {}".format(
                site_name,
                scan_agent,
                scan_occurence.date(),
                start_time,
                nmap_command,
                result_file_base_name,
            )
        )

        # Add entry to ScheduledScan model.
        django_connector.ScheduledScan.objects.get_or_create(
            site_name=site_name,
            scan_agent=scan_agent,
            start_time=start_time,
            nmap_command=nmap_command,
            targets_file=targets_file,
            result_file_base_name=result_file_base_name,
            # scan_status='pending',
            # completed_time=,
        )


if __name__ == "__main__":
    main()
    print("[+] Done!")
