#!/usr/bin/env python3
"""
Loosely inspired by: https://github.com/CBHue/nMap_Merger/blob/master/nMapMerge.py

If you want to use this as a module you need to pass main a list of nmap XML files.

xml_scans = [
    "/home/scantron/console/scan_results/complete/test__engine1__1_of_3_20200924_1533.xml",
    "/home/scantron/console/scan_results/complete/test__engine2__2_of_3_20200924_1533.xml",
    "/home/scantron/console/scan_results/complete/test__engine3__3_of_3_20200924_1533.xml",
]

merge_nmap_xml_files.main(xml_files=xml_files, merged_filename="my_combined_scans.xml")
"""
# Standard Python libraries.
import argparse
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET

# Third party Python libraries.

# Custom Python libraries.


def add_header(merged_filename, start_epoch, version, xmloutputversion):
    """Add header to final XML file."""

    print("Adding header")

    #     scan_dict = scan_report.get_dict()
    #     version = scan_dict.get("version", "")
    #     summary = scan_report.summary

    #     try:
    #         start_string = summary.split(";")[0].split(" ", 3)[3]
    #     except:
    #         start_string = ""

    #     commandline = scan_dict.get("commandline", "")
    #     started = scan_report.started
    #     scan_type = scan_dict.get("scan_type", "")

    #     nmap_header = f"""<?xml version='1.0' encoding='UTF-8'?>
    # <!DOCTYPE nmaprun>
    # <?xml-stylesheet href='file:///usr/bin/../share/nmap/nmap.xsl' type='text/xsl'?>
    # <nmaprun scanner='nmap' args='{commandline}' start='{started}' startstr='{start_string}' version='{version}' xmloutputversion='1.04'>
    # <scaninfo type='{scan_type}' protocol='tcp' numservices="" services=''/>
    # <verbose level='0'/>
    # <debugging level='0'/>"""

    nmap_header = '<?xml version="1.0" encoding="UTF-8"?>'
    nmap_header += "<!DOCTYPE nmaprun>"
    nmap_header += '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>'
    nmap_header += f'<nmaprun scanner="nmap" args="" start="{start_epoch}" startstr="" version="{version}" xmloutputversion="{xmloutputversion}">'
    nmap_header += '<scaninfo type="" protocol="" numservices="" services=""/>'
    nmap_header += '<verbose level=""/>'
    nmap_header += '<debugging level=""/>\n'

    with open(merged_filename, "w") as fh:
        fh.write(nmap_header)


def merge_nmap_results(xml_file, merged_filename):
    """Merge in results from multiple XML files into one combined XML file."""

    hosts = 0

    with open(merged_filename, mode="a", encoding="utf-8") as merged_filename_fh:

        with open(xml_file) as fh:

            print(f"Merging results from file: {xml_file}")

            nmap_xml = ET.parse(fh)

            for host in nmap_xml.findall("host"):
                hosts = hosts + 1
                nmap_host = ET.tostring(host, encoding="unicode", method="xml")
                merged_filename_fh.write(nmap_host)
                merged_filename_fh.flush()

    return hosts


def add_footer(finished_epoch, merged_filename):
    """Add footer to final XML file."""

    print("Adding footer")

    nmap_footer = (
        f'<runstats><finished time="{finished_epoch}" timestr="" elapsed="" summary="" exit="success"/></runstats>'
    )
    nmap_footer += "</nmaprun>"

    with open(merged_filename, "a") as fh:
        fh.write(nmap_footer)


def main(xml_files, merged_filename=""):
    """Given a list of XML files to merge, returns the string of the final merged XML file."""

    # Track the number of hosts found.  Not currently used.
    hosts = 0

    # Check to ensure xml_files is not empty.
    if not xml_files:
        print("No XML files were found.")
        return ""

    # Remove potential duplicate files.
    xml_files = list(set(xml_files))

    try:
        # Generate the final XML file name if not provided.
        if not merged_filename:
            # Create the merged filename.
            now = time.localtime()
            timestamp = time.strftime("%Y%m%d_%H%M%S", now)
            merged_filename = f"nmap_merged_{timestamp}.xml"

        # Determine the earliest start time and latest stop time to populate the final XML file.
        # xml_files = [
        #     "pool1__engine1__1_of_3_20201030_1439.xml",
        #     "pool1__engine2__3_of_3_20201030_1439.xml",
        #     "pool1__engine3__2_of_3_20201030_1439.xml",
        # ]

        start_epoch_list = []
        finished_epoch_list = []

        for xml_file in xml_files:
            with open(xml_file, "r") as fh:
                nmap_xml = ET.parse(fh)
                root = nmap_xml.getroot()
                start_epoch_list.append(int(root.get("start")))
                finished_epoch_list.append(int(nmap_xml.find("runstats")[0].get("time")))

        start_epoch = min(start_epoch_list)  # Pick the smallest/earliest start time.
        finished_epoch = max(finished_epoch_list)  # Pick the largets/latest stop time.

        print(f"Earliest starting epoch is {start_epoch} from: {start_epoch_list}")
        print(f"Latest finishing epoch is {finished_epoch} from: {finished_epoch_list}")

        # Extract the version/xmloutputversion from the last XML file in the for loop, shouldn't vary so there's no
        # need to be picky.
        version = root.get("version")
        xmloutputversion = root.get("xmloutputversion")

        # Add header.
        add_header(merged_filename, start_epoch, version, xmloutputversion)

        # Loop through XML files and add content.
        for xml_file in xml_files:
            if xml_file.endswith(".xml"):
                logging.debug(f"Parsing: {xml_file}")
                host_in_xml_file = merge_nmap_results(xml_file, merged_filename)
                hosts += host_in_xml_file

        # Add footer.
        add_footer(finished_epoch, merged_filename)

        print(f"Final merged file: {merged_filename}")

    except Exception as e:
        print(f"Exception: {e}")
        merged_filename = ""

    return merged_filename


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Merge nmap XML scan result files into one XML file.")
    parser.add_argument(
        "-d", dest="directory", action="store", required=True, help="Merge all XML files in a specified directory"
    )
    args = parser.parse_args()

    xml_files_set = set()

    if os.path.isdir(args.directory):

        path = args.directory

        for file_name in os.listdir(path):
            if file_name.endswith(".xml"):
                fullname = os.path.join(path, file_name)
                print(f"Adding: {fullname}")
                xml_files_set.add(fullname)
    else:
        print(f"Not a directory: {args.directory}")
        sys.exit(1)

    # Pass set of XML files to main.
    main(xml_files_set)
