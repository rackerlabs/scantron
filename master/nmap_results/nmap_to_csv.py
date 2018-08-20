#!/usr/bin/env python
import csv
import glob
import os
import re
import shutil

from libnmap.parser import NmapParser


class ScanEvent():

    # Variables that will eventually be fields in Splunk.
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
    output = output.replace('.xml', '.csv')
    if len(events) != 0:
        # print(output)
        # print(events)

        header_fields = ['#starttime', 'endtime', 'siteName', 'scanner', 'dest_ip', 'transport', 'dest_port', 'app', 'service', 'state']

        with open(output, 'w') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header_fields)

            for event in events:
                writer.writerow(event.to_list())


def main():
    root_dir = "/home/scantron/master"

    # Build directory paths.
    complete_dir = os.path.join(root_dir, "nmap_results", "complete")
    processed_dir = os.path.join(root_dir, "nmap_results", "processed")
    for_splunk_dir = os.path.join(root_dir, "for_splunk")

    # Grab all scan files.
    scans = os.listdir(complete_dir)

    # Grab a list of XMLfiles from the "complete" folder.
    xml_scans = glob.glob(os.path.join(complete_dir, "*.xml"))

    # Loop through all valid xml files and export them to csv files.
    for scan in xml_scans:
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

                    # Regular expression to grab site name and scanner based off the filename.
                    match = re.search('(\S+_)(office|customer)_', os.path.basename(scan))
                    event.site_name = match.group(1).rstrip('_')
                    event.scanner = match.group(2)

                    # Extract port and service information.
                    event.address = host.address
                    event.transport = service.protocol
                    event.port = service.port
                    event.app = service.service
                    event.state = service.state

                    data = service.service_dict
                    event.app_version = ""
                    if 'product' in data:
                        event.app_version += data['product'] + " "
                    if 'version' in data:
                        event.app_version += data['version'] + " "
                    if 'extrainfo' in data:
                        event.app_version += data['extrainfo']

                    events.append(event)

        # The file has been completely parsed...create csv files in 'for_splunk' directory.
        export_to_csv(events, os.path.join(for_splunk_dir, os.path.basename(scan)))

    # csv files have been created, move all nmap scan file types from "completed" to "processed" folder.
    for name in scans:
        shutil.move(
            os.path.join(os.path.join(complete_dir, name)),
            os.path.join(os.path.join(processed_dir, name))
        )


if __name__ == "__main__":
    main()
