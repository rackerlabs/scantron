#!/usr/bin/env python

# Standard Python libraries.
import datetime
import ipaddress
import itertools
import logging
import pytz
import sys

# Third party Python libraries.
from django.conf import settings

# Custom Python libraries.
import django_connector


# Setup logging.
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ROOT_LOGGER = logging.getLogger()


def clean_text(uncleaned_text):
    """Clean text by replacing specific characters."""

    cleaned_text = uncleaned_text.lower().replace(" - ", "_").replace("-", "_").replace(" ", "_").replace("/", "_")

    # Ensures __ can be used as a delimiter to extract site name, engine, and timestamp in the
    # console/scan_results/masscan_json_to_csv.py and console/scan_results/nmap_to_csv.py scripts.
    while "__" in cleaned_text:
        cleaned_text = cleaned_text.replace("__", "_")

    return cleaned_text


def is_ip_address(ip):
    """Takes an IP address returns True/False if it is a valid IPv4 or IPv6 address."""

    ip = str(ip)

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def is_ip_network(address, strict=False):
    """Takes an address returns True/False if it is a valid network."""

    address = str(address)

    try:
        ipaddress.ip_network(address, strict)
        return True

    except ValueError:
        return False


def distribute(included_targets_as_list_size, total_scan_engines_in_pool):
    """Distribute targets to scan engines as evenly as possible.  Generates a list of targets per engine.  For example,
    if there are 13 targets and 3 scan engines, this function will return [5, 4 ,4] - 5 targets for engine1, 4
    targets for engine2, and 4 targets for engine3.

    https://stackanswers.net/questions/distribute-an-integer-amount-by-a-set-of-slots-as-evenly-as-possible
    """

    base, extra = divmod(included_targets_as_list_size, total_scan_engines_in_pool)
    return [base + (i < extra) for i in range(total_scan_engines_in_pool)]


def schedule_scan(scan_dict):
    """Given a scan dictionary, try and schedule the scan."""

    # The ScheduledScan model acts as the sanitized endpoint for engines to determine scan jobs.  We don't want to
    # expose the other models, so we populate that ScheduledScan model instead.  The actual exposed fields for the API
    # are controlled using console/api/serializers.py.

    # Ensure none of the values are empty.  blank=False is only enforced through forms, which this method of creating a
    # scheduled scan does not honor.
    empty_scan_dict_value_detected = False

    for key, value in scan_dict.items():

        # Ignore fields that are allowed to be empty.
        if key in ["excluded_targets", "pooled_scan_result_file_base_name", "scan_binary_process_id"]:
            continue

        if not value:
            ROOT_LOGGER.error(f"scan_dict['{key}'] has an empty value.")
            empty_scan_dict_value_detected = True

    if empty_scan_dict_value_detected:
        return

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


def main():

    # Determine time variables to assist in filtering.
    now_datetime = datetime.datetime.now()
    now_time = now_datetime.time()
    now_time_hour = now_time.hour
    now_time_minute = now_time.minute

    # Only filter on scans that should start at this time based off hour and minute, ignoring seconds.
    # If minute is the time resolution, this script (wrapped with scan_scheduler.sh) must be executed every minute
    # through cron.  Also filter on scans that are enabled.  We can't filter on occurrences using Django's filter()
    # method; it will have to be checked using logic below.
    scans = (
        django_connector.Scan.objects.filter(start_time__hour=now_time_hour)
        .filter(start_time__minute=now_time_minute)
        .filter(enable_scan=True)
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
        # Site model as a foreign key, and in turn, the Site model has foreign keys for the Engine and ScanCommand
        # models (see the scantron_model_graph.png for a visualization).  Therefore, if a field from the Engine or
        # ScanCommand models is updated, it will update the Site model, and cascade to the Scan model.

        # Scan model.
        scan_start_time = scan.start_time

        # ScanCommand model.
        scan_command = scan.site.scan_command.scan_command
        scan_binary = scan.site.scan_command.scan_binary

        # Site model.
        site_name = scan.site.site_name

        # Generate timestamps
        #####################

        # start_datetime is a DateTimeField in ScheduledScan, but the Scan model only contains start_time (TimeField)
        # and a recurrence date, so we have to build a DateTimeField equivalent.
        # Build start_datetime based off Django's TIME_ZONE setting.
        # https://www.saltycrane.com/blog/2009/05/converting-time-zones-datetime-objects-python/#add-timezone-localize
        start_datetime_tz_naive = datetime.datetime.combine(scan_occurrence.date(), scan_start_time)
        start_datetime = pytz.timezone(settings.TIME_ZONE).localize(start_datetime_tz_naive)

        # Convert start_datetime datetime object to string for result_file_base_name.
        timestamp = datetime.datetime.strftime(start_datetime, "%Y%m%d_%H%M")

        # Excluded Targets.
        ###################

        # Convert excluded_targets string to list to reduce duplicates later.
        excluded_targets = scan.site.excluded_targets.split()

        # Convert queryset to a list of strings (where each string may contain more than 1 target).
        globally_excluded_targets_objects = list(
            django_connector.GloballyExcludedTarget.objects.all().values_list("globally_excluded_targets", flat=True)
        )

        # Initialize empty list.
        globally_excluded_targets = []

        # globally_excluded_targets_objects may look like ["1.2.3.4 50.60.70.80", "www.example.com"], so we need to loop
        # through each string in the list, split on space (if applicable), in order to build a new list.
        for get in globally_excluded_targets_objects:
            targets = get.split(" ")
            for target in targets:
                globally_excluded_targets.append(target)

        # Combine both excluded lists, cast as set to reduce duplicates, re-cast as list, and sort targets.
        all_excluded_targets = sorted(list(set(excluded_targets + globally_excluded_targets)))

        # masscan --excludefile can only contain IP addresses.  If the scan_binary is masscan, remove non-IP addresses
        # from all_excluded_targets.
        if scan_binary == "masscan":

            # Create a temporary list of valid IP addresses.
            all_excluded_targets_temp = []

            for excluded_target in all_excluded_targets:
                if is_ip_address(excluded_target) or is_ip_network(excluded_target):
                    all_excluded_targets_temp.append(excluded_target)
                else:
                    ROOT_LOGGER.info(
                        f"masscan can only scan IPs.  Removed target '{excluded_target}' from excluded targets."
                    )

            all_excluded_targets = all_excluded_targets_temp

        # Convert to a string.  strip() removes any prepended or trailing spaces.
        all_excluded_targets_string = " ".join(all_excluded_targets).strip()

        # Included Targets
        ##################

        # masscan -iL argument file can only contain IP addresses.  If the scan_binary is masscan, remove non-IP
        # addresses from included_targets.
        if scan_binary == "masscan":

            # Convert from string to list of targets.
            included_targets_list = scan.site.targets.split()

            # Create a temporary list of valid IP addresses.
            included_targets_temp = []

            for included_target in included_targets_list:
                if is_ip_address(included_target) or is_ip_network(included_target):
                    included_targets_temp.append(included_target)
                else:
                    ROOT_LOGGER.info(
                        f"masscan can only scan IPs.  Removed target '{included_target}' from included targets."
                    )

            # Convert to a string.  strip() removes any prepended or trailing spaces.
            included_targets = " ".join(included_targets_temp).strip()

            # Don't schedule a masscan scan if no valid IP targets are provided.
            if not included_targets:
                ROOT_LOGGER.error(f"No valid IP targets specified for a masscan scan...not scheduling scan ID {scan}.")
                continue

        else:
            included_targets = scan.site.targets

        # Scan Engine / Scan Engine Pool Logic
        ######################################

        # Single scan engine selected.
        if scan.site.scan_engine:
            scan_engine = scan.site.scan_engine.scan_engine

            # Build result_file_base_name file.  "__" is used by console/scan_results/nmap_to_csv.py to .split()
            # site_name and scan_engine.
            result_file_base_name = f"{clean_text(site_name)}__{clean_text(scan_engine)}__{timestamp}"

            scan_dict = {
                "site_name": site_name,
                "start_time": scan_start_time,
                "scan_engine": scan_engine,
                "start_datetime": start_datetime,
                "scan_binary": scan_binary,
                "scan_command": scan_command,
                "targets": included_targets,
                "excluded_targets": all_excluded_targets_string,
                "result_file_base_name": result_file_base_name,
                "pooled_scan_result_file_base_name": "",
                "scan_status": "pending",
                "scan_binary_process_id": 0,
            }

            schedule_scan(scan_dict)

        # Scan engine pool selected.
        elif scan.site.scan_engine_pool:

            # Create the pooled scan file that will contain the other pooled scans.
            if scan_binary == "nmap":
                pooled_scan_result_file_base_name = f"{clean_text(site_name)}__pooled__{timestamp}.xml"
            elif scan_binary == "masscan":
                pooled_scan_result_file_base_name = f"{clean_text(site_name)}__pooled__{timestamp}.json"

            """This is bit confusing to follow, but this code evenly distributes the targets among X number of scan
            engines.  An example list of "targets" [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] is used to assist in
            following the logic.
            """

            # Convert string of targets to list so it can be sliced up.
            # included_targets_as_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
            included_targets_as_list = included_targets.split()

            # Determine the total number of targets.
            # included_targets_as_list_size = 13
            included_targets_as_list_size = len(included_targets_as_list)

            # Retrieve all engines in the pool.
            scan_engines_in_pool = scan.site.scan_engine_pool.scan_engines.all()

            # Determine the number of engines in the pool.
            # total_scan_engines_in_pool = 3
            total_scan_engines_in_pool = scan_engines_in_pool.count()

            # Create a list of the number of targets per engine.
            # number_of_targets_per_scan_engine = [5, 4, 4]
            number_of_targets_per_scan_engine = distribute(included_targets_as_list_size, total_scan_engines_in_pool)

            # Create a list of lists with the targets evenly distributed.
            # https://www.geeksforgeeks.org/python-split-a-list-into-sublists-of-given-lengths/
            # targets_per_scan_engine = [
            #     [1, 2, 3, 4, 5],  # Engine 1 targets
            #     [6, 7, 8, 9],  # Engine 2 targets
            #     [10, 11, 12, 13]  # Engine 3 targets
            # ]
            # included_targets_iterator must be assigned outside of itertools.islice()
            included_targets_iterator = iter(included_targets_as_list)
            targets_per_scan_engine = [
                list(itertools.islice(included_targets_iterator, i)) for i in number_of_targets_per_scan_engine
            ]

            # Loop through the list of lists to add new scan jobs.
            for index, targets_scanned_by_scan_engine in enumerate(targets_per_scan_engine):

                # Since targets_per_scan_engine is already broken down into total_scan_engines_in_pool lists, just use
                # the index to assign an engine.
                scan_engine = scan_engines_in_pool[index].scan_engine

                # Build result_file_base_name file.
                result_file_base_name = (
                    f"{clean_text(site_name)}__{clean_text(scan_engine)}__{timestamp}.part{index + 1}"
                )
                # print(index, targets_scanned_by_scan_engine, result_file_base_name)

                # Convert list of targets back to a string.
                included_targets = " ".join(targets_scanned_by_scan_engine).strip()

                scan_dict = {
                    "site_name": site_name,
                    "start_time": scan_start_time,
                    "scan_engine": scan_engine,
                    "start_datetime": start_datetime,
                    "scan_binary": scan_binary,
                    "scan_command": scan_command,
                    "targets": included_targets,
                    "excluded_targets": all_excluded_targets_string,
                    "result_file_base_name": result_file_base_name,
                    "pooled_scan_result_file_base_name": pooled_scan_result_file_base_name,
                    "scan_status": "pending",
                    "scan_binary_process_id": 0,
                }

                schedule_scan(scan_dict)

        else:
            ROOT_LOGGER.critical(f"No engine or engine pool found...exiting.")
            sys.exit(1)


if __name__ == "__main__":

    ROOT_LOGGER.setLevel(10)  # DEBUG

    # Log file handling.
    file_handler = logging.FileHandler("scan_scheduler.log")
    file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(file_handler)

    # console logging.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    main()

    ROOT_LOGGER.info("Done!")
