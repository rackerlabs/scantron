"""
Utility methods for other scripts to use.
"""
# Standard Python libraries.
import logging
from logging import handlers

# Third party Python libraries.
from django.conf import settings
from django.core.mail import send_mail

# Custom Python libraries.
import django_connector


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

# https://github.com/pennersr/django-allauth/blob/7b81531bc89ae98dc6f687611743db5b36cda9a2/allauth/account/adapter.py#L448


def process_scan_status_change(queue_object):
    """When a scan finishes, execute other tasks based off settings."""

    logger.info(f"queue_object: {process_scan_status_change}")

    # Extract values from passed dictionary.
    scheduled_scan_id = queue_object["scheduled_scan_id"]
    scan_status = queue_object["scan_status"]

    # Look up scheduled scan information.
    scheduled_scan = django_connector.ScheduledScan.objects.filter(id=scheduled_scan_id)[0]

    # Determine Site ID.
    site_id = scheduled_scan.site_name_id

    # Determine the scan binary used.
    scan_binary = scheduled_scan.scan_binary

    # Retrieve site information.
    site = django_connector.Site.objects.filter(id=site_id)[0]

    # Determine if site has email_scan_alerts enabled.
    email_scan_alerts = site.email_scan_alerts

    # 1) Does an email alert need to be sent?
    if email_scan_alerts:

        from_address = settings.EMAIL_HOST_USER
        to_addresses = site.email_alert_address.split(",")
        subject = f"Scantron scan {scan_status.upper()}: {site.site_name}"

        if scan_status == "completed":

            # Provide different links based off the scan binary used.
            if scan_binary == "nmap":
                body = f"""XML: http://127.0.0.1/results/{scheduled_scan.id}?file_type=xml
NMAP: http://127.0.0.1/results/{scheduled_scan.id}?file_type=nmap
"""
            else:
                body = f"""Results: http://127.0.0.1/results/{scheduled_scan.id}?file_type=json"""

        elif scan_status in ["started", "error"]:
            body = f""""""

        # Ignore "pending" status.  Shouldn't ever reach this branch.
        else:
            pass

        # email_sent_successfully = custom_send_email(to_addresses, subject=subject, body=body)
        email_sent_successfully = send_mail(subject, body, from_address, to_addresses, fail_silently=False,)

        if not email_sent_successfully:
            logger.error(f"Issue sending the email for Scheduled Scan ID: {scheduled_scan_id}")

        logger.info(f"Successfully sent email for Scheduled Scan ID: {scheduled_scan_id}")

    # 2 Do other stuff
    # TODO
