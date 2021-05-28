#!/usr/bin/env python
# Standard Python libraries.
import argparse
import datetime
import glob
import logging
import os
import sys

# Third party Python libraries.
import django

# Custom Python libraries.
import django_connector

# Setup logging.
ROOT_LOGGER = logging.getLogger()
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")


def delete_files_in_dir(folder):
    """Delete all the files in a directory."""

    logging.info("Deleting files in folder: {}".format(folder))
    file_list = os.listdir(folder)
    for f in file_list:
        os.remove(os.path.join(folder, f))


def main(
    database_remove, file_remove, scan_retention_in_minutes, max_queryset_size_to_delete, disable_dryrun, verbosity,
):
    """Execute main function."""

    # Assign log level.
    ROOT_LOGGER.setLevel((6 - verbosity) * 10)

    # Setup file logging.
    script_name = os.path.basename(os.path.abspath(__file__))
    log_file_handler = logging.FileHandler(f"{script_name.split('.py')[0]}.log")
    log_file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(log_file_handler)

    # Setup console logging.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    ROOT_LOGGER.info(f"Starting {script_name} script.")

    if not django_connector.Configuration.objects.filter(id=1)[0].enable_scan_retention:
        ROOT_LOGGER.info("Scan retention is disabled.  Exiting...")
        return

    ROOT_LOGGER.info(f"Disable dryrun setting: {disable_dryrun}")

    # Utilize Django's timezone aware setting to return a datetime object.
    now = django.utils.timezone.now()

    # Retrieve scan retention value from Configuration if it is not specified.
    # 60 * 24 = 1440 minutes in a day.
    if not scan_retention_in_minutes:
        scan_retention_in_minutes = (60 * 24) * (django_connector.Configuration.objects.all()[0].scan_retention_in_days)

    ROOT_LOGGER.info(f"Removing scans older than {scan_retention_in_minutes} minutes.")

    # Calculate the datetime "scan_retention_in_minutes" ago in the past.
    datetime_retention_in_minutes = now - datetime.timedelta(minutes=scan_retention_in_minutes)

    # Initialize scan_retention_dict as empty dictionary.
    scan_retention_dict = {}

    # Filter for scans that meet the retention criteria.
    scans_older_than_retention_date = django_connector.ScheduledScan.objects.filter(
        scan_status__in=["cancelled", "completed", "error"]
    ).filter(completed_time__lt=datetime_retention_in_minutes)

    if database_remove:

        # Determine the total number of scans to delete.
        scans_older_than_retention_date_size = scans_older_than_retention_date.count()
        ROOT_LOGGER.info(f"{scans_older_than_retention_date_size} scans will be removed from the database.")

        if disable_dryrun:

            if scans_older_than_retention_date_size < (max_queryset_size_to_delete + 1):

                scan_retention_dict["database"] = ()

                try:
                    database_result = scans_older_than_retention_date.delete()
                    scan_retention_dict["database"] = database_result
                    ROOT_LOGGER.info(
                        f"Successfully deleted {scans_older_than_retention_date_size} scans from the database."
                    )

                except Exception as e:
                    ROOT_LOGGER.exception(f"Problem deleting scans from database using .delete().  Exception: {e}")

            else:
                ROOT_LOGGER.warning(
                    f"The number of scans to delete ({scans_older_than_retention_date_size}) is greater than the "
                    f"specified max_queryset_size_to_delete ({max_queryset_size_to_delete}).  Using an iterator for "
                    "better memory management."
                )

                # Utilize an iterator for better memory management.
                # https://medium.com/@hansonkd/performance-problems-in-the-django-orm-1f62b3d04785
                total_iterator_scans_deleted = 0

                for scan in scans_older_than_retention_date.iterator():
                    try:
                        # Capture scan ID.
                        scan_id = scan.id
                        scan.delete()
                        ROOT_LOGGER.debug(f"Scan ID successfully deleted: {scan_id}")
                        total_iterator_scans_deleted += 1

                    except Exception as e:
                        ROOT_LOGGER.exception(f"Problem deleting scan from database using iterator().  Exception: {e}")

                ROOT_LOGGER.info(f"Successfully deleted {total_iterator_scans_deleted} scans from the database.")

    if file_remove:

        # Build directory paths.
        root_dir = "/home/scantron/console"
        complete_dir = os.path.join(root_dir, "scan_results", "complete")
        processed_dir = os.path.join(root_dir, "scan_results", "processed")
        cancelled_dir = os.path.join(root_dir, "scan_results", "cancelled")
        bigdata_analytics_dir = os.path.join(root_dir, "for_bigdata_analytics")

        # Loop through each scan.
        for scan in scans_older_than_retention_date:

            result_file_base_name = scan.result_file_base_name

            # Grab a list of files from the "complete" directory.
            complete_dir_scans = glob.glob(os.path.join(complete_dir, f"{result_file_base_name}*"))

            # Grab a list of files from the "processed" directory.
            processed_dir_scans = glob.glob(os.path.join(processed_dir, f"{result_file_base_name}*"))

            # Grab a list of files from the "cancelled" directory.
            cancelled_dir_scans = glob.glob(os.path.join(cancelled_dir, f"{result_file_base_name}*"))

            # Grab a list of .csv files from the "for_bigdata_analytics" directory.
            bigdata_analytics_dir_csv_files = glob.glob(
                os.path.join(bigdata_analytics_dir, f"{result_file_base_name}.csv")
            )

            for file_to_delete in (
                complete_dir_scans + processed_dir_scans + cancelled_dir_scans + bigdata_analytics_dir_csv_files
            ):
                ROOT_LOGGER.debug(f"Deleting file: {file_to_delete}")
                if disable_dryrun:
                    try:
                        os.remove(file_to_delete)
                    except OSError:
                        ROOT_LOGGER.error(f"Could not delete file: {file_to_delete}")

    ROOT_LOGGER.info(f"scan_retention_dict: {scan_retention_dict}")
    ROOT_LOGGER.info(f"{script_name} is done!")

    return scan_retention_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Remove scan data, targets, and results older than a specified date.")
    parser.add_argument(
        "-b",
        dest="database_remove",
        action="store_true",
        required=False,
        default=False,
        help="Remove scan database entries.",
    )
    parser.add_argument(
        "-c",
        dest="file_remove",
        action="store_true",
        required=False,
        default=False,
        help=(
            "Remove target_files/*.targets, target_files/*.excluded_targets, scan_results/*, and "
            "for_bigdata_analytics/*.csv files"
        ),
    )
    parser.add_argument(
        "-o",
        dest="scan_retention_in_minutes",
        action="store",
        required=False,
        type=int,
        help="Delete emails older than X minutes.  WARNING: Overrides the configuration setting.",
    )
    parser.add_argument(
        "-m",
        dest="max_queryset_size_to_delete",
        action="store",
        required=False,
        type=int,
        default=500,
        help=(
            "Max number of records to try and delete through Django's ORM .delete() function, otherwise a memory "
            "efficient iterator must be used."
        ),
    )
    parser.add_argument(
        "-r", dest="disable_dryrun", action="store_true", required=False, default=False, help="Disable dryrun option."
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        action="store",
        type=int,
        default=4,
        help="Verbosity level (0=NOTSET, 1=CRITICAL, 2=ERROR, 3=WARNING, 4=INFO, 5=DEBUG,).  Default: 4",
    )
    args = parser.parse_args()

    if (args.scan_retention_in_minutes is not None) and (args.scan_retention_in_minutes <= 0):
        print("Scan retention in days must be greater than 0...exiting.")
        sys.exit(0)

    main(**vars(args))
