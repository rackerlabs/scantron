#!/usr/bin/env python

# Standard Python libraries.
import argparse
import datetime

# Third party Python libraries.
from django.utils.timezone import localtime

# Custom Python libraries.
import django_connector


def main(number_of_days_in_the_future=5, scan_id=None):

    # Set current date and time variables.  Example datetime objects are provided throughout.

    # datetime.datetime(2021, 5, 3, 10, 21, 53, 197844, tzinfo=<DstTzInfo 'America/Chicago' CDT-1 day, 19:00:00 DST>)
    now_datetime = localtime()

    # datetime.time(10, 21, 53, 197844)
    now_time = now_datetime.time()

    # Filter on specified scan ID or all enabled scans.
    if scan_id:
        scans = django_connector.Scan.objects.filter(id=scan_id)
    else:
        scans = django_connector.Scan.objects.filter(enable_scan=True)

    for scan in scans:

        # Standardize the exdates.  Just a note: https://github.com/django-recurrence/django-recurrence/issues/70
        for index, exdate in enumerate(scan.recurrences.exdates):
            updated_exdate = localtime(exdate).replace(hour=now_time.hour).replace(minute=now_time.minute)
            print(f"Old exdate: {exdate} -- new exdate {updated_exdate}")
            scan.recurrences.exdates[index] = updated_exdate

        # datetime.datetime(2021, 5, 3, 0, 0)
        beginning_of_today = now_datetime.replace(hour=0).replace(minute=0).replace(second=0).replace(microsecond=0)

        # datetime.datetime(2021, 5, 3, 23, 59, 59)
        future_end_datetime = beginning_of_today + datetime.timedelta(days=number_of_days_in_the_future)

        # dtstart is time zone aware since it's coming from Django.
        # datetime.datetime(2021, 5, 3, 15, 24, tzinfo=<DstTzInfo 'America/Chicago' CDT-1 day, 19:00:00 DST>)
        dtstart = localtime(scan.dtstart)

        # Retrieve all ths scan occurrences.
        scan_occurrences = scan.recurrences.between(beginning_of_today, future_end_datetime, dtstart=dtstart, inc=True)

        if scan_occurrences:

            print(f"Scan ID: {scan.id}")
            print(f"Scan start time: {scan.start_time}")
            print(f"{len(scan_occurrences)} total scans between {beginning_of_today} and {future_end_datetime}")

            for scan_occurrence in scan_occurrences:
                print(f"\t{scan_occurrence}")

            if scan.recurrences.exdates:
                print("exdates")
                for exdate in scan.recurrences.exdates:
                    print(f"\t{exdate}")

            print("=" * 20)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Visualize the scan start dates and times from the beginning of today to a specified number of days in the "
            "future for enabled scans."
        )
    )
    parser.add_argument(
        "-d",
        dest="number_of_days_in_the_future",
        action="store",
        type=int,
        default=5,
        help="Number of days in the future.  Default 5.",
    )
    parser.add_argument(
        "-s", dest="scan_id", action="store", type=int, required=False, help="Specify a scan ID.",
    )
    args = parser.parse_args()

    main(**vars(args))
