#!/usr/bin/env python
# Standard Python libraries.
import csv
import glob
import os
import shutil

# Third party Python libraries.
from libnmap.parser import NmapParser

# Custom Python libraries.


# Used when the column names from result_dict cannot be extracted.
CSV_FIELD_NAMES = [
    "openports",
    "start_time",
    "end_time",
    "site_name",
    "engine",
    "scan_binary",
    "target",
    "protocol",
    "port",
    "service_name",
    "banner",
    "state",
]


def write_results_to_csv_file(results_list, csv_file_name):
    """Writes results to a .csv file.  Attempts to extract column names, falls back to CSV_FIELD_NAMES."""

    print(f"Writing results to: {csv_file_name}")

    with open(csv_file_name, "w") as csvfile:
        try:
            field_names = results_list[0].keys()
        except IndexError:
            field_names = CSV_FIELD_NAMES

        writer = csv.DictWriter(csvfile, fieldnames=field_names)
        writer.writeheader()

        if results_list:
            for result in results_list:
                writer.writerow(result)

        # Rackspace specific column, feel free to disregard.
        # There are no open ports, but still write a value "no" to the file for the "openports" column.  This allows the
        # big data analytics platform agent to identify a non-empty file, consume it, and send to the platform.
        # Otherwise, it would ignore the empty .csv file, in which we can't distinguish if there are no actual open
        # ports from "did the scan actually work and we didn't receive any results?".
        else:
            writer.writerow({"openports": "no"})

    print(f"Done writing results to: {csv_file_name}")


def main():

    # Build directory paths.
    root_dir = "/home/scantron/console"
    complete_dir = os.path.join(root_dir, "scan_results", "complete")
    processed_dir = os.path.join(root_dir, "scan_results", "processed")
    bigdata_analytics_dir = os.path.join(root_dir, "for_bigdata_analytics")

    # Grab a list of xml files from the "complete" folder.
    xml_scans = glob.glob(os.path.join(complete_dir, "*.xml"))

    # Loop through all valid xml files and export them to csv files, then move them to the "processed" directory.
    for scan in xml_scans:

        try:

            # "scan" variable is constructed as "result_file_base_name" in console/scan_scheduler.py
            scan_file_name = os.path.basename(scan)
            site_name = scan_file_name.split("__")[0]
            engine = scan_file_name.split("__")[1]

            # Extract the base file name from the .xml scan file name.
            base_scan_file_name = os.path.basename(scan).split(".xml")[0]

            # Build the .csv file name.
            csv_file_name = f"{base_scan_file_name}.csv"

            results_list = []
            report = NmapParser.parse_fromfile(scan)

            # Loop through all hosts in xml file. Create result_dict objects storing the necessary information.
            for host in report.hosts:

                # Loop through services for each host.
                if len(host.services) != 0:

                    for service in host.services:

                        result_dict = {
                            "openports": "yes",  # Rackspace specific column, feel free to disregard.
                            "start_time": report.started,
                            "end_time": report.endtime,
                            "site_name": site_name,
                            "engine": engine,
                            "scan_binary": "nmap",
                            "target": host.address,
                            "protocol": service.protocol,
                            "port": service.port,
                            "service_name": service.service,
                            "banner": "",  # Populated below.
                            "state": service.state,
                        }

                        service_dict = service.service_dict

                        if "product" in service_dict:
                            result_dict["banner"] += f"{service_dict['product']}"
                        if "version" in service_dict:
                            result_dict["banner"] += f"{service_dict['version']}"
                        if "extrainfo" in service_dict:
                            result_dict["banner"] += f"{service_dict['extrainfo']}"

                        results_list.append(result_dict)

            # The file has been completely parsed...create csv files in "for_bigdata_analytics" directory.
            write_results_to_csv_file(results_list, os.path.join(bigdata_analytics_dir, csv_file_name))

            # Find all the .nmap, .xml, and .gnmap files for the base_scan_file_name.
            base_scan_files = glob.glob(os.path.join(complete_dir, f"{base_scan_file_name}*"))

            # csv files have been created, move all nmap scan file types from "completed" to "processed" folder.
            # Extract file name and rebuild full path for destination.
            for scan_file in base_scan_files:
                shutil.move(
                    scan_file,  # source
                    os.path.join(os.path.join(processed_dir, scan_file.split("/")[-1])),  # destination
                )

        except Exception as e:
            print(f"Exception processing file: {scan}.  Exception: {e}")


if __name__ == "__main__":
    main()
