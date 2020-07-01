#!/usr/bin/env python
# Standard Python libraries.
import csv
import glob
import os
import shutil

# Third party Python libraries.
from libnmap.parser import NmapParser

# Custom Python libraries.


class ScanEvent:

    # Variables that will eventually be fields in big data analytics platform.
    def __init__(self):
        self.start_time = ""
        self.end_time = ""
        self.site_name = ""
        self.scanner = ""
        self.address = ""
        self.transport = ""
        self.port = ""
        self.app = ""
        self.app_version = ""
        self.state = ""

    def to_list(self):
        output = []
        output.append(self.start_time)
        output.append(self.end_time)
        output.append(self.site_name)
        output.append(self.scanner)
        output.append(self.address)
        output.append(self.transport)
        output.append(self.port)
        output.append(self.app)
        output.append(self.app_version)
        output.append(self.state)

        return output


def export_to_csv(events, output):
    output = output.replace(".xml", ".csv")
    if len(events) != 0:

        header_fields = [
            "starttime",
            "endtime",
            "siteName",
            "scanner",
            "dest_ip",
            "transport",
            "dest_port",
            "app",
            "service",
            "state",
        ]

        with open(output, "w") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header_fields)

            for event in events:
                writer.writerow(event.to_list())


def main():
    root_dir = "/home/scantron/console"

    # Build directory paths.
    complete_dir = os.path.join(root_dir, "scan_results", "complete")
    processed_dir = os.path.join(root_dir, "scan_results", "processed")
    bigdata_analytics_dir = os.path.join(root_dir, "for_bigdata_analytics")

    # Grab a list of xml files from the "complete" folder.
    xml_scans = glob.glob(os.path.join(complete_dir, "*.xml"))

    # Loop through all valid xml files and export them to csv files, then move them to the "processed" directory.
    for scan in xml_scans:

        try:
            events = []
            report = NmapParser.parse_fromfile(scan)

            # Loop though all hosts in xml file. Create event objects storing the necessary information.
            for host in report.hosts:
                # Loop through services for each host.
                if len(host.services) != 0:
                    for service in host.services:
                        event = ScanEvent()
                        event.start_time = report.started
                        event.end_time = report.endtime

                        # "scan" variable is constructed as "result_file_base_name" in console/scan_scheduler.py
                        scan_file_name = os.path.basename(scan)
                        event.site_name = scan_file_name.split("__")[0]
                        event.scanner = scan_file_name.split("__")[1]

                        # Extract port and service information.
                        event.address = host.address
                        event.transport = service.protocol
                        event.port = service.port
                        event.app = service.service
                        event.state = service.state

                        data = service.service_dict
                        event.app_version = ""
                        if "product" in data:
                            event.app_version += f"{data['product']}"
                        if "version" in data:
                            event.app_version += f"{data['version']}"
                        if "extrainfo" in data:
                            event.app_version += f"{data['extrainfo']}"

                        events.append(event)

            # The file has been completely parsed...create csv files in "for_bigdata_analytics" directory.
            export_to_csv(events, os.path.join(bigdata_analytics_dir, os.path.basename(scan)))

            # Extract the base file name from the .xml scan file name.
            base_scan_file_name = os.path.basename(scan).split(".xml")[0]

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
