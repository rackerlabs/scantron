"""
Utility methods for other scripts to use.
"""
# Standard Python libraries.
import datetime
import fnmatch
import json
import logging
import os
import shutil
from logging import handlers

# Third party Python libraries.
from django.conf import settings
from django.core.mail import send_mail

# Custom Python libraries.
import django_connector
import pyndiff
from scan_results import masscan_json_to_csv, merge_masscan_json_files, merge_nmap_xml_files, nmap_to_csv

# Setup logging configuration.
logger = logging.getLogger("rq.worker")
verbosity = 4  # INFO
log_level = (6 - verbosity) * 10
backup_count = 10
max_size_megabytes = 500
log_file_name = "utility.py.log"

# fmt: off
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        handlers.RotatingFileHandler(
            log_file_name,
            maxBytes=(max_size_megabytes * 1024) * 1024,
            backupCount=backup_count,
            delay=True,
        ),
    ],
)
# fmt: on


def datetime_object_to_string_converter(datetime_object):
    """Convert a datetime object to a string."""

    if isinstance(datetime_object, datetime.datetime):
        return datetime_object.__str__()


def move_wildcard_files(wildcard_filename, source_directory, destination_directory):
    """Move files with supported fnmatch patterns (* and ?)."""

    file_list = os.listdir(source_directory)

    for file_name in file_list:
        if fnmatch.fnmatch(file_name, wildcard_filename):
            shutil.move(os.path.join(source_directory, file_name), os.path.join(destination_directory, file_name))


def process_scan_status_change(scheduled_scan_dict):
    """When a scan finishes, execute other tasks based off settings."""

    logger.info(f"scheduled_scan_dict: {scheduled_scan_dict}")

    # Extract values from passed ScheduleScan object.
    scheduled_scan_id = scheduled_scan_dict["id"]
    scan_status = scheduled_scan_dict["scan_status"]
    scan_binary = scheduled_scan_dict["scan_binary"]
    start_datetime = scheduled_scan_dict["start_datetime"]
    result_file_base_name = scheduled_scan_dict["result_file_base_name"]

    # Retrieve site information.
    site_name = scheduled_scan_dict["site_name"]
    site = django_connector.Site.objects.filter(site_name=site_name)[0]

    # Determine if site has email_scan_alerts enabled.
    email_scan_alerts = site.email_scan_alerts

    # 1) Does an email alert need to be sent?
    if email_scan_alerts:

        console_fqdn = settings.CONSOLE_FQDN
        from_address = settings.EMAIL_HOST_USER
        to_addresses = site.email_alert_addresses.split(",")
        subject = f"Scantron scan {scan_status.upper()}: {site_name}"

        if scan_status == "completed":

            # Provide different links based off the scan binary used.
            if scan_binary == "nmap":
                body = f"""XML: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=xml
NMAP: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=nmap
"""
            else:
                body = f"""Results: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=json"""

        elif scan_status in ["started", "paused", "cancelled", "error"]:
            body = """"""

        # Ignore "pending" status.  Shouldn't ever reach this branch.
        else:
            pass

        # Add additional scan info.
        body += f"""
Debug scan info:
{json.dumps(scheduled_scan_dict, indent=4, sort_keys=False, default=datetime_object_to_string_converter)}
"""
        logger.info(f"Email body: {body}")

        # email_sent_successfully = custom_send_email(to_addresses, subject=subject, body=body)
        email_sent_successfully = send_mail(
            subject,
            body,
            from_address,
            to_addresses,
            fail_silently=False,
        )

        if not email_sent_successfully:
            logger.error(f"Issue sending the email for Scheduled Scan ID: {scheduled_scan_id}")

        logger.info(f"Successfully sent email for Scheduled Scan ID: {scheduled_scan_id}")

    # If a scan engine pool is used, ensure all the pooled scans are complete before combining the XML/JSON files.
    if site.scan_engine_pool and scan_status == "completed":

        pooled_scan_result_file_base_name = scheduled_scan_dict["pooled_scan_result_file_base_name"]

        # Ensure no scans are still running in the pool.  To do that, filter on the site name, start date, and start
        # time.  Can't filter on the start_datetime datetime.datetime object directly, must be broken up into the
        # .date() and .time() components.
        pooled_scheduled_scans = (
            django_connector.ScheduledScan.objects.filter(site_name=site_name)
            .filter(start_datetime__contains=start_datetime.date())
            .filter(start_datetime__contains=start_datetime.time())
        )

        # Loop through all the pooled scans and collect the ones that are not complete.
        not_completed_pooled_scans = []

        for pooled_scheduled_scan in pooled_scheduled_scans:
            if pooled_scheduled_scan.scan_status != "completed":
                not_completed_pooled_scans.append(pooled_scheduled_scan.result_file_base_name)

        # If one of the scans isn't done done yet, just return.
        if not_completed_pooled_scans:
            logger.info(f"Still waiting on {not_completed_pooled_scans}")
            return

        # ALL POOLED SCANS FOR A SITE ARE DONE AT THIS POINT!  Time to combine the results based off the scan binary.
        # This will combine XML files for nmap and JSON files for masscan.

        # Split on "." when scan_scheduler.py adds ".partX".  Doesn't matter which of the partX files is used here.
        base_name = pooled_scheduled_scan.result_file_base_name.split(".")[0]
        # TODO make sure "." not allowed in site or engine names.
        # Split on "__".
        base_name_parts = base_name.split("__")
        # base_name_parts[0] = site name
        # base_name_parts[1] = engine
        # base_name_parts[2] = start date

        # Collect all files in "complete" directory.
        # processed_dir = "/home/scantron/console/scan_results/processed"
        complete_dir = "/home/scantron/console/scan_results/complete"
        files_in_complete_dir = os.listdir(complete_dir)

        # Collect all unique files in a set.
        files_to_merge = set()

        if scan_binary == "nmap":
            match_criteria = f"{base_name_parts[0]}__*__{base_name_parts[2]}.part*.xml"

            for file_name in files_in_complete_dir:
                if fnmatch.fnmatch(file_name, match_criteria):
                    files_to_merge.add(os.path.join(complete_dir, file_name))

            if not files_to_merge:
                logger.error(f"No files to merge with match criteria: {match_criteria}")
                return

            # Convert from a set to a list.
            files_to_merge = list(files_to_merge)

            # Merge into 1 final XML file.
            final_merged_filename = merge_nmap_xml_files.main(
                xml_files=files_to_merge, merged_filename=os.path.join(complete_dir, pooled_scan_result_file_base_name)
            )

            # merge_nmap_xml_files.main() returns an empty string if it is not successful.
            if final_merged_filename:
                logger.info(f"Successfully merged XML files {files_to_merge} into {final_merged_filename}")
            else:
                logger.error(f"Error merging XML files {files_to_merge}")
                return

        elif scan_binary == "masscan":
            match_criteria = f"{base_name_parts[0]}__*__{base_name_parts[2]}.part*.json"

            for file_name in files_in_complete_dir:
                if fnmatch.fnmatch(file_name, match_criteria):
                    files_to_merge.add(os.path.join(complete_dir, file_name))

            if not files_to_merge:
                logger.error(f"No files to merge with match criteria: {match_criteria}")
                return

            # Convert from a set to a list.
            files_to_merge = list(files_to_merge)

            # Merge into 1 final JSON file.
            final_merged_filename = merge_masscan_json_files.main(
                json_files=files_to_merge,
                merged_filename=os.path.join(complete_dir, pooled_scan_result_file_base_name),
                pretty_print_json=True,
            )

            if final_merged_filename:
                logger.info(f"Successfully merged JSON files {files_to_merge} into {final_merged_filename}")
            else:
                logger.error(f"Error merging JSON files {files_to_merge}")
                return

    # 2) Convert scan results to .csv for big data analytics.
    # Calling the functions here instead of relying on cron job that runs every minute.  The scripts also moves the
    # .xml files from console/scan_results/complete to console/scan_results/processed
    if scan_status == "completed":
        if scan_binary == "nmap":
            nmap_to_csv.main()
        elif scan_binary == "masscan":
            masscan_json_to_csv.main()

    # 3) Does an nmap scan diff need to be sent?
    # Determine if site has email_scan_alerts enabled.
    email_scan_diff = site.email_scan_diff

    if scan_binary == "nmap" and email_scan_diff and scan_status == "completed":

        # Determining the previous scan is a little trickier with pooled scans.
        if site.scan_engine_pool:

            # Retrieve all past scans, sorted by most recent to oldest.  Ensure completed_time is not NULL.
            past_scans = (
                django_connector.ScheduledScan.objects.filter(site_name=site_name)
                .filter(completed_time__isnull=False)
                .order_by("-completed_time")
            )

            # Assign latest_scans_pooled_scan_result_file_base_name to the most recent scan's
            # pooled_scan_result_file_base_name value.
            latest_scans_pooled_scan_result_file_base_name = past_scans[0].pooled_scan_result_file_base_name

            # Loop through the remaining scans, starting at the next one.  If the pooled_scan_result_file_base_name
            # value changes, the previous scan has been found, so set previous_scan_found to True and bail on the for
            # loop.
            previous_scan_found = False

            for past_scan in past_scans[1:]:
                if past_scan.pooled_scan_result_file_base_name != latest_scans_pooled_scan_result_file_base_name:
                    previous_scan_found = True
                    break

            if previous_scan_found:
                previous_scan = past_scan
                logger.info(f"previous scan ID: {previous_scan}")

            else:
                logger.warning("This is the first scan to complete for the site, there are no previous ones")
                return

        else:
            # Retrieve the previous ScheduledScan object for a Site.  [0] will be the scan that just completed, so use
            # [1] to retrieve the previous one.
            try:
                previous_scan = django_connector.ScheduledScan.objects.filter(site_name=site_name).order_by(
                    "-completed_time"
                )[1]
                logger.info(f"previous scan ID: {previous_scan}")

            except IndexError:
                logger.warning("This is the first scan to complete for the site, there are no previous ones")
                return

        # Specify root path to files.
        root_dir = "/home/scantron/console/scan_results/processed"

        # Previous scan file.
        # Handle pooled scan results.
        if site.scan_engine_pool:
            previous_scan_result_file_name = f"{previous_scan.pooled_scan_result_file_base_name}"
        # Non-pooled scan results.
        else:
            previous_scan_result_file_name = f"{previous_scan.result_file_base_name}.xml"

        previous_scan_result_file_path = os.path.join(root_dir, f"{previous_scan_result_file_name}")
        logger.info(f"previous_scan_result_file_path: {previous_scan_result_file_path}")

        # Latest scan file.
        # Pooled scan result.
        if site.scan_engine_pool and final_merged_filename:
            latest_scan_result_file_name = scheduled_scan_dict["pooled_scan_result_file_base_name"]
        # Non-pooled scan results.
        else:
            latest_scan_result_file_name = f"{result_file_base_name}.xml"

        latest_scan_result_file_path = os.path.join(root_dir, f"{latest_scan_result_file_name}")
        logger.info(f"latest_scan_result_file_path: {latest_scan_result_file_path}")

        # Compare nmap XML files.
        change_summary = pyndiff.generate_diff(
            previous_scan_result_file_path,
            latest_scan_result_file_path,
            ignore_udp_open_filtered=False,
            output_type="xml",
            write_summary_to_disk_for_xml_output_type=False,
            verbose=False,
            step_debug=False,
        )

        # Ensure change_summary actually has information.
        if change_summary:
            logger.info(f"pyndiff results:\n\n{change_summary}")

            from_address = settings.EMAIL_HOST_USER
            to_addresses = site.email_scan_diff_addresses.split(",")
            subject = f"Scantron diff results for {site_name}"

            email_sent_successfully = send_mail(
                subject,
                change_summary,
                from_address,
                to_addresses,
                fail_silently=False,
            )

            if not email_sent_successfully:
                logger.error(f"Issue sending scan diff email to: {to_addresses}")
                return

            logger.info(f"Successfully sent scan diff email to: {to_addresses}")

        else:
            logger.info("change_summary value from pyndiff is empty...not sending an email")
