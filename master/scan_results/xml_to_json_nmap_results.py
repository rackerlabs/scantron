#!/usr/bin/env python
"""
Convert an nmap XML file to a JSON file and return a JSON dictionary object.
"""

# Standard Python libraries.
import argparse
import json
import time
from xml.etree.cElementTree import parse

# Third party Python libraries.
import xmljson


# Custom Python libraries.


def get_timestamp():
    """Generates a timestamp."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)

    return timestamp


def main(xml_input_file, json_output_file, pretty_print_json):
    """Given an XML input file, create an output JSON file.  Also returns a dictionary object if used as a module.

    Arguments:
        input_file {string} -- Input XML file.
        output_file {string} -- Output XML file.
    """

    json_data = []

    try:
        with open(xml_input_file, "r") as fh_xml:
            with open(json_output_file, "w") as fh_json:

                xmljson_object = xmljson.XMLData()

                if pretty_print_json:
                    json.dump(xmljson_object.data(parse(fh_xml).getroot()), fh_json, indent=4)
                else:
                    json.dump(xmljson_object.data(parse(fh_xml).getroot()), fh_json)

        # Load file as a json object to return.
        with open(json_output_file, "r") as fh:
            json_data = json.load(fh)

    except Exception as e:
        print(f"[-] Exception: {e}")

    return json_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert an nmap XML file to a JSON file and return a JSON dictionary object."
    )
    parser.add_argument("-i", dest="xml_input_file", action="store", required=True, help="Input .xml file.")
    parser.add_argument("-o", dest="json_output_file", action="store", required=False, help="Output .json file.")
    parser.add_argument(
        "-p",
        dest="pretty_print_json",
        action="store_true",
        default=False,
        required=False,
        help="Pretty print .json file.  Results in larger file, but it's easier to read.",
    )

    args = parser.parse_args()

    if not args.json_output_file:
        # Strip .xml file extension, add datetimestamp, append .json.
        args.json_output_file = f"{args.xml_input_file.split('.')[0]}_{get_timestamp()}.json"

    main(**vars(args))
