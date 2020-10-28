"""
Utility methods for other scripts to use.
"""
# Standard Python libraries.
import fnmatch
import logging
import os
import shutil
from logging import handlers

# Third party Python libraries.
from django.conf import settings
from django.core.mail import send_mail

# Custom Python libraries.
import django_connector
from scan_results import nmap_to_csv, masscan_json_to_csv

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
        subject = f"Scantron scan {scan_status.upper()}: {site.site_name}"

        if scan_status == "completed":

            # Provide different links based off the scan binary used.
            if scan_binary == "nmap":
                body = f"""XML: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=xml
NMAP: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=nmap
"""
            else:
                body = f"""Results: https://{console_fqdn}/results/{scheduled_scan_id}?file_type=json"""

        elif scan_status in ["started", "paused", "cancelled", "error"]:
            body = f""""""

        # Ignore "pending" status.  Shouldn't ever reach this branch.
        else:
            pass

        # email_sent_successfully = custom_send_email(to_addresses, subject=subject, body=body)
        email_sent_successfully = send_mail(subject, body, from_address, to_addresses, fail_silently=False,)

        if not email_sent_successfully:
            logger.error(f"Issue sending the email for Scheduled Scan ID: {scheduled_scan_id}")

        logger.info(f"Successfully sent email for Scheduled Scan ID: {scheduled_scan_id}")

    # 2) Convert scan results to .csv for big data analytics.
    # Calling the functions here instead of relying on cron job that runs every minute.  The scripts also moves the
    # .xml files from console/scan_results/complete to console/scan_results/processed
    if scan_status == "completed":
        if scan_binary == "nmap":
            nmap_to_csv.main()
        elif scan_binary == "masscan":
            masscan_json_to_csv.main()
