"""
Utility methods for other scripts to use.
"""
# Standard Python libraries.
import email
import json
import logging
from logging import handlers
import os
import smtplib

from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Third party Python libraries.

# Custom Python libraries.
import django_connector


# Load secrets.
with open("scantron_secrets.json", "r") as fh:
    SECRETS = json.loads(fh.read())

# Setup logging configuration.
logger = logging.getLogger("rq.worker")
verbosity = 5
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

        to_addresses = site.email_alert_address
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

        email_sent_successfully = send_email(to_addresses, subject=subject, body=body)

        if not email_sent_successfully:
            logger.error(f"Issue sending the email for Scheduled Scan ID: {scheduled_scan_id}")

        logger.info(f"Successfully sent email for Scheduled Scan ID: {scheduled_scan_id}")

    # 2 Do other stuff
    # TODO


def send_email(
    to_addresses,  # This is expecting a comma separated string, not a list.
    subject="",
    body="",
    attachments={},
    from_address="",
    smtp_server="127.0.0.1",
    port=25,
    debug=False,
):
    """Specifies the default email config, and sends an email. Returns True if the email is sent successfully, False
    otherwise."""

    if not isinstance(to_addresses, str):
        logger.error("to_addresses must be a comma separated string of addresses.")
        return False

    if not isinstance(from_address, str):
        logger.error("from_address must be a string.")
        return False

    smtp_settings = SECRETS["smtp_settings"]

    # Create an SMTP server instance.
    server = smtplib.SMTP(smtp_settings["SMTP_HOST"], smtp_settings["SMTP_PORT"])

    # Enable debugging option.
    if debug:
        server.set_debuglevel(True)

    # Use an encrypted connection.
    server.ehlo()
    server.starttls()

    message = MIMEMultipart()
    message["From"] = from_address
    message["To"] = to_addresses
    message["Subject"] = subject

    for a in attachments:

        file = MIMEBase("application", "octet-stream")

        try:

            with open(attachments[a], "rb") as f:
                file.set_payload(f.read())
                file.add_header("Content-Disposition", "attachment", filename=os.path.basename(attachments[a]))

        except (FileNotFoundError, OSError, ValueError):
            file.set_payload(attachments[a])
            file.add_header("Content-Disposition", "attachment", filename=a)

        email.encoders.encode_base64(file)
        message.attach(file)

    message.attach(MIMEText(body))

    try:
        server.sendmail(from_address, to_addresses.split(","), message.as_string())
        server.quit()
        logger.info(f"Email '{subject}' successfully sent to: {to_addresses}")

    except Exception as e:
        logger.error("Error sending email: {}".format(e))
        return False

    return True
