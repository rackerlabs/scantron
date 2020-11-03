#!/usr/bin/env python3
"""
If you want to use this as a module you need to pass main a list of masscan .json files.

json_files = [
    "/home/scantron/console/scan_results/complete/test__engine1__1_of_3_20200924_1533.json",
    "/home/scantron/console/scan_results/complete/test__engine2__2_of_3_20200924_1533.json",
    "/home/scantron/console/scan_results/complete/test__engine3__3_of_3_20200924_1533.json",
]

merge_masscan_json_files.main(json_files, "my_combined_scans.json")
"""
# Standard Python libraries.
import argparse
import json
import os
import sys
import time

# Third party Python libraries.

# Custom Python libraries.


def main(json_files, merged_filename="", pretty_print_json=True):
    """Given a list of JSON files to merge, returns the string of the final merged JSON file."""

    # Check to ensure xml_files is not empty.
    if not json_files:
        print("No JSON files were found.")
        return ""

    # Remove potential duplicate files.
    json_files = list(set(json_files))

    try:
        # Generate the final XML file name if not provided.
        if not merged_filename:
            # Create the merged filename.
            now = time.localtime()
            timestamp = time.strftime("%Y%m%d_%H%M%S", now)
            merged_filename = f"masscan_merged_{timestamp}.json"

        final_json_list = []

        for json_file in json_files:

            if os.path.getsize(json_file) == 0:
                print(f"File is 0 bytes: {json_file}")
                continue

            with open(json_file, "r") as fh_json_file:
                final_json_list.extend(json.load(fh_json_file))

        with open(merged_filename, "w") as fh:
            if pretty_print_json:
                json.dump(final_json_list, fh, indent=4)
            else:
                json.dump(final_json_list, fh)

        print(f"Final merged file: {merged_filename}")

    except Exception as e:
        print(f"Exception: {e}")
        merged_filename = ""

    return merged_filename


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Merge masscan JSON scan result files into one JSON file.")
    parser.add_argument(
        "-d", dest="directory", action="store", required=True, help="Merge all JSON files in a specified directory"
    )
    parser.add_argument(
        "-p",
        dest="pretty_print_json",
        action="store_true",
        default=False,
        required=False,
        help="Pretty print .json file.  Results in larger file, but it's easier to read.",
    )
    args = parser.parse_args()

    json_files_set = set()

    if os.path.isdir(args.directory):

        path = args.directory

        for file_name in os.listdir(path):
            if file_name.endswith(".json"):
                fullname = os.path.join(path, file_name)
                print(f"Adding: {fullname}")
                json_files_set.add(fullname)
    else:
        print(f"Not a directory: {args.directory}")
        sys.exit(1)

    # Pass set of JSON files to main.
    main(json_files_set)
