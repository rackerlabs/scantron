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
from django.utils.timezone import localtime

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

    # Set current date and time variables.

    # datetime.datetime(2021, 5, 3, 10, 21, 53, 197844)
    now_datetime = datetime.datetime.now()

    # datetime.time(10, 21, 53, 197844
    now_time = now_datetime.time()

    # Filter on enabled scans only.  We can't filter on occurrences using Django's .filter() method; it will have to
    # be checked using logic below.  Author's reason why .filter() can't be used:
    # https://github.com/django-recurrence/django-recurrence/issues/91#issuecomment-286890133
    scans = django_connector.Scan.objects.filter(enable_scan=True)

    if not scans:
        ROOT_LOGGER.info("No scans enabled")
        return

    # Loop through each scan to determine if it is supposed to be scheduled.
    for scan in scans:

        """
        Have fun understanding the documentation for django-recurrence!

        https://django-recurrence.readthedocs.io/en/latest/

        This is a challenging library to work with since the django-recurrence README states "The recurrence field only
        deals with recurrences not with specific time information."  That's why a separate Scan.start_time field is
        required.  A recurrence object has a granularity of a date, and does not include time, so some challenging logic
        is required to determine a one-off scan (no recurring schedule) vs. a recurring scan (with a possible hourly
        frequency).  When using scan.recurrence.between(), the start and end values are python datetime objects with a
        date granularity, so time is completely ignored.  Thus, a dtstart seed datetime object for recurrences is used.

        The author has stated "I don't actually use this library now - so my support here is mostly just merging fixes
        where I am comfortable with them, and pushing releases to PyPI. If someone else wants to take over ownership,
        I'd be more than happy to hand it over."
        (https://github.com/django-recurrence/django-recurrence/issues/163#issuecomment-604111964)

        I've tried to provide verbose comments to explain my reasoning, but every time I come back to this code and
        library, it takes me a day to figure out what's going on.
        """

        # datetime.datetime(2021, 5, 1, 0, 0)
        beginning_of_today = now_datetime.replace(hour=0).replace(minute=0).replace(second=0).replace(microsecond=0)

        # datetime.datetime(2021, 5, 3, 23, 59, 59)
        end_of_today = now_datetime.replace(hour=23).replace(minute=59).replace(second=59).replace(microsecond=0)

        # dtstart is time zone aware since it's coming from Django.  Strip out the tzinfo to make it usable with both
        # beginning_of_today and end_of_today.
        # datetime.datetime(2021, 5, 3, 15, 24, tzinfo=<UTC>)
        dtstart = localtime(scan.dtstart).replace(tzinfo=None)

        # Retrieve all ths scan occurrences.
        scan_occurrences = scan.recurrences.between(beginning_of_today, end_of_today, dtstart=dtstart, inc=True)

        # If no scan occurrences exist given the datetime parameters, move on to the next potential scan.
        if not scan_occurrences:
            continue

        # Pare down now_datetime (datetime.datetime(2021, 5, 3, 10, 21, 53, 197844)) to include just the date and time
        # datetime.datetime(2021, 5, 3, 10, 21)
        now_datetime_stripped = now_datetime.replace(second=0).replace(microsecond=0)

        # Further pare down the datetime object to just include a date and no time datetime.datetime(2021, 5, 3, 0, 0),
        # for single one-off scans.  In these cases, there isn't a recurrence since it is a one-time event.
        now_datetime_stripped_only_date = now_datetime_stripped.replace(hour=0).replace(minute=0)

        # datetime.time(10, 21)
        now_time_stripped = now_time.replace(second=0).replace(microsecond=0)

        # Scans with an occurrence.
        if now_datetime_stripped in scan_occurrences:
            schedule_this_scan = True

        # Single one-off scans with a start time that matches the current time and date in scan_occurrences.
        elif (scan.start_time.replace(second=0) == now_time_stripped) and (
            now_datetime_stripped_only_date in scan_occurrences
        ):
            schedule_this_scan = True

        # Scan scheduling criteria wasn't met.
        else:
            schedule_this_scan = False

        # If the scheduled_scan bit was not set to True, move on.
        if not schedule_this_scan:
            continue

        # Let's extract the remaining variables from existing database relationships.  Note that the Scan model has the
        # Site model as a foreign key, and in turn, the Site model has foreign keys for the Engine and ScanCommand
        # models (see the scantron_model_graph.png for a visualization).  Therefore, if a field from the Engine or
        # ScanCommand models is updated, it will update the Site model, and cascade to the Scan model.

        # Scan model.
        # For the current scan_start_time, use now_time_stripped instead of scan.start_time in case an hourly recurrence
        # frequency is used.
        scan_start_time = now_time_stripped

        # Site model.
        site_name = scan.site.site_name

        ROOT_LOGGER.info(f"Found scan for {site_name} at {scan_start_time}.")

        # ScanCommand model.
        scan_command = scan.site.scan_command.scan_command
        scan_binary = scan.site.scan_command.scan_binary

        # Generate timestamps
        #####################

        # start_datetime is a DateTimeField in ScheduledScan, but the Scan model only contains start_time (TimeField)
        # and a recurrence date, so we have to build a DateTimeField equivalent.
        # Build start_datetime based off Django's TIME_ZONE setting.
        # https://www.saltycrane.com/blog/2009/05/converting-time-zones-datetime-objects-python/#add-timezone-localize
        start_datetime = pytz.timezone(settings.TIME_ZONE).localize(now_datetime)

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
            ROOT_LOGGER.critical("No engine or engine pool found...exiting.")
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

    ROOT_LOGGER.info("scan_scheduler.py started")

    main()

    ROOT_LOGGER.info("scan_scheduler.py completed")
