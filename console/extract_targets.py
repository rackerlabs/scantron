"""Extract FQDNs, IPv4, and IPv6 networks/addresses from a string or file."""

# Standard Python libraries.
import argparse
import ipaddress
import json
import os
import sys

# Third party Python libraries.
import fqdn
import requests
import tld

# Custom Python libraries.

__version__ = "1.0.0"


def is_ip_address(ip):
    """Returns True/False if a string is a valid IPv4 or IPv6 address."""

    ip = str(ip)

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def is_ipv4_address(ip):
    """Returns True/False if a string is a valid IPv4 address."""

    ip = str(ip)

    try:
        if ipaddress.ip_address(ip).version == 4:
            return True

        else:
            return False

    except ValueError as e:
        print(f"{e}")


def is_ipv6_address(ip):
    """Returns True/False if a string is a valid IPv6 address."""

    ip = str(ip)

    try:
        if ipaddress.ip_address(ip).version == 6:
            return True

        else:
            return False

    except ValueError as e:
        print(f"{e}")


def is_ip_network(network, strict=False):
    """Returns True/False if a string is a valid network."""

    network = str(network)

    try:
        ipaddress.ip_network(network, strict)
        return True

    except ValueError:
        return False


def is_valid_fqdn(domain):
    """Return True/False if a provided domain is a valid FQDN, not necessarily if it contains a valid top level domain."""

    domain_is_valid_fqdn = fqdn.FQDN(domain).is_valid

    return domain_is_valid_fqdn


def domain_has_valid_fqdn(domain):
    """Return True/False if a FQDN has a valid top level domain (TLD)."""

    try:
        tld.get_tld(domain, fix_protocol=True)
        return True

    except tld.exceptions.TldDomainNotFound:
        return False


def retrieve_cloudflare_ip_networks(
    retrieve_new_data=False, cloudflare_filename="cloudflare_ip_networks.txt", write_to_disk=True
):
    """Retrieve the IPv4 and IPv6 ranges for Cloudflare servers.

    https://www.cloudflare.com/ips/
    """

    cloudflare_dict = {
        "list_of_strings": set(),
        "list_of_ipaddress_objects": set(),
    }

    # If cloudflare_filename already exists and fresh data isn't requested.
    if os.path.exists(cloudflare_filename) and not retrieve_new_data:

        print(f"File already exists: {cloudflare_filename}")

        with open(cloudflare_filename, "r") as fh:
            for ip_network in fh.readlines():
                cloudflare_dict["list_of_ipaddress_objects"].add(ipaddress.ip_network(ip_network.strip()))

    else:

        for ip_version in ["4", "6"]:

            print(f"Retrieving Cloudflare IPv{ip_version} networks")

            url = f"https://www.cloudflare.com/ips-v{ip_version}"
            response = requests.get(url, timeout=2, verify=True)

            if response.status_code == 200:
                text = response.text

                for ip_network in text.strip().split("\n"):
                    cloudflare_dict["list_of_ipaddress_objects"].add(ipaddress.ip_network(ip_network))

            else:
                print("Cloudflare IP networks could not be retrieved.")

    # Return a list of sorted IPv4 and IPv6 networks.
    # See https://docs.python.org/3/library/ipaddress.html#ipaddress.get_mixed_type_key
    cloudflare_dict["list_of_ipaddress_objects"] = sorted(
        cloudflare_dict["list_of_ipaddress_objects"], key=lambda obj: ipaddress.get_mixed_type_key(obj)
    )

    # Convert ipaddress objects to strings.
    cloudflare_dict["list_of_strings"] = [str(obj) for obj in cloudflare_dict["list_of_ipaddress_objects"]]

    # Only write to disk if fresh data is requested.
    if write_to_disk and retrieve_new_data:
        print(f"Writing CloudFront IP networks to disk: {cloudflare_filename}")
        with open(cloudflare_filename, "w") as fh:
            for ip_network in cloudflare_dict["list_of_strings"]:
                fh.write(f"{ip_network}\n")

    # print(f"cloudflare_dict: {cloudflare_dict}")

    return cloudflare_dict


def retrieve_amazon_cloudfront_ip_ranges(
    retrieve_new_data=False, aws_cloudfront_filename="aws_cloudfront_ip_networks.txt", write_to_disk=True
):
    """Retrieve the IPv4 and IPv6 ranges for AWS' CloudFront servers.

    https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
    """

    cloudfront_dict = {
        "list_of_strings": set(),
        "list_of_ipaddress_objects": set(),
    }

    # If aws_cloudfront_filename already exists and fresh data isn't requested.
    if os.path.exists(aws_cloudfront_filename) and not retrieve_new_data:

        print(f"File already exists: {aws_cloudfront_filename}")

        with open(aws_cloudfront_filename, "r") as fh:
            for ip_network in fh.readlines():
                cloudfront_dict["list_of_ipaddress_objects"].add(ipaddress.ip_network(ip_network.strip()))

    else:

        print("Retrieving IPv4 and IPv6 network ranges for AWS' CloudFront servers.")

        url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        response = requests.get(url, verify=True)

        if response.status_code == 200:
            json_data = response.json()

            for service in json_data["prefixes"]:
                if service["service"] == "CLOUDFRONT":
                    cloudfront_dict["list_of_ipaddress_objects"].add(ipaddress.ip_network(service["ip_prefix"]))

            for service in json_data["ipv6_prefixes"]:
                if service["service"] == "CLOUDFRONT":
                    cloudfront_dict["list_of_ipaddress_objects"].add(ipaddress.ip_network(service["ipv6_prefix"]))

        else:
            print("CloudFront IP networks could not be retrieved.")

    # Return a list of sorted IPv4 and IPv6 networks.
    # See https://docs.python.org/3/library/ipaddress.html#ipaddress.get_mixed_type_key
    cloudfront_dict["list_of_ipaddress_objects"] = sorted(
        cloudfront_dict["list_of_ipaddress_objects"], key=lambda obj: ipaddress.get_mixed_type_key(obj)
    )

    # Convert ipaddress objects to strings.
    cloudfront_dict["list_of_strings"] = [str(obj) for obj in cloudfront_dict["list_of_ipaddress_objects"]]

    # Only write to disk if fresh data is requested.
    if write_to_disk and retrieve_new_data:
        print(f"Writing CloudFront IP networks to disk: {aws_cloudfront_filename}")
        with open(aws_cloudfront_filename, "w") as fh:
            for ip_network in cloudfront_dict["list_of_strings"]:
                fh.write(f"{ip_network}\n")

    # print(f"cloudfront_dict: {cloudfront_dict}")

    return cloudfront_dict


def retrieve_cdn_ip_networks(retrieve_new_data=False):
    """Create a list of CDN IPv4 and IPv6 networks."""

    # Collect all CDN networks.
    cdn_ip_networks = []

    # Retrieve AWS' CloudFront CDN IP networks.
    cloudfront_dict = retrieve_amazon_cloudfront_ip_ranges(retrieve_new_data)
    cdn_ip_networks += cloudfront_dict["list_of_ipaddress_objects"]

    # Retrieve Cloudflare's CDN IP networks.
    cloudflare_dict = retrieve_cloudflare_ip_networks(retrieve_new_data)
    cdn_ip_networks += cloudflare_dict["list_of_ipaddress_objects"]

    # Return a list of sorted IPv4 and IPv6 networks.
    # See https://docs.python.org/3/library/ipaddress.html#ipaddress.get_mixed_type_key
    cdn_ip_networks = sorted(cdn_ip_networks, key=lambda obj: ipaddress.get_mixed_type_key(obj))

    return cdn_ip_networks


class TargetExtractor:
    def __init__(
        self,
        delimiter="",
        targets_string=None,
        targets_file=None,
        exclude_private_ips=False,
        sort_targets=False,
        exclude_cdn_ip_networks=False,
        retrieve_new_cdn_ip_data=False,
        write_to_disk=False,
    ):
        self.delimiter = delimiter
        self.targets_string = str(targets_string).strip()
        self.targets_file = targets_file
        self.exclude_private_ips = exclude_private_ips
        self.sort_targets = sort_targets
        self.exclude_cdn_ip_networks = exclude_cdn_ip_networks
        self.retrieve_new_cdn_ip_data = retrieve_new_cdn_ip_data
        self.write_to_disk = write_to_disk

        if self.exclude_cdn_ip_networks:
            self.cdn_ip_networks = retrieve_cdn_ip_networks(self.retrieve_new_cdn_ip_data)

        # Read targets from file as string.
        if self.targets_file:
            with open(self.targets_file, "r") as fh:
                self.targets_string = fh.read().strip()

        self.targets_dict = self.extract_targets(self.targets_string)

    # def expand_range_of_ips(self, start_ip, end_ip):
    #     """Takes an IP range and returns all the IPs in that range.
    #     # http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
    #     """

    #     ip_range = []

    #     if (ipaddress.ip_address(start_ip).version == 6) or (ipaddress.ip_address(end_ip).version == 6):
    #         print(f"IPv6 IP range not supported in this function: {start_ip} - {end_ip}")
    #         return ip_range

    #     start = list(map(int, start_ip.split(".")))
    #     end = list(map(int, end_ip.split(".")))
    #     temp = start

    #     ip_range.append(start_ip)
    #     while temp != end:
    #         start[3] += 1
    #         for i in (3, 2, 1):
    #             if temp[i] == 256:
    #                 temp[i] = 0
    #                 temp[i - 1] += 1
    #         ip_range.append(".".join(map(str, temp)))

    #     return ip_range

    def update_disallowed_target(self, targets_dict, target):
        """Update disallowed target list."""

        targets_dict["disallowed_targets"].add(target)

    def extract_targets(self, targets_string):
        """Extracts valid domains and IPv4/IPv6 addresses/networks from a string."""

        # Dictionary to track valid, invalid, and disallowed targets.  All sets are eventually converted to lists.
        targets_dict = {
            "ipv4_addresses": {
                "as_list": set(),
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "ipv4_networks": {
                "as_list": set(),
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "ipv6_addresses": {
                "as_list": set(),
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "ipv6_networks": {
                "as_list": set(),
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "domains": {
                "as_list": set(),
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "invalid_targets": set(),
            "invalid_targets_total": 0,
            "disallowed_targets": set(),
            "disallowed_targets_total": 0,
            "as_list": [],
            "as_csv": "",
            "as_nmap": "",
            "total": 0,
        }

        # Split on delimiter if provided.
        if self.delimiter:
            print(f'Using delimiter: "{self.delimiter}"')
            target_list = targets_string.split(self.delimiter)
        else:
            target_list = targets_string.split()

        for target in target_list:

            # Check if target is an IP address.
            if is_ip_address(target):

                # If so, convert it to an ipaddress.ip_address object.
                ip_address = ipaddress.ip_address(target)

                if ip_address.is_multicast:
                    print(f"IP address is a multicast IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                elif ip_address.is_loopback:
                    print(f"IP address is a loopback IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                # Cloud metadata IPs are covered under this as well: 169.254.169.254
                elif ip_address.is_link_local:
                    print(f"IP address is a link local IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                # Lastly, check if it is a RFC1918 IP address.  169.254.169.254 will be flagged as
                # private (which it technically is) instead of link local if this check is first.  This check is saved
                # for last.
                if ip_address.is_private and self.exclude_private_ips:
                    print(f"IP address is private IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                # Double-check and make sure IP is not a public IP (and thus it's private) if private IPs are not
                # allowed...probably redundant.
                if not ip_address.is_global and self.exclude_private_ips:
                    print(f"IP address is not a public IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                # Check if IP is in a CDN network.
                if self.exclude_cdn_ip_networks:

                    cdn_ip_found = False

                    # Not efficient to loop through each CDN network, but necessary to test if an ip_address
                    # (ipaddress.ip_address object) is in a network (ipaddress.IPv4Network or ipaddress.IPv6Network).
                    # Note that self.cdn_ip_networks is a mix of IPv4 and IPv6 networks.
                    for cdn_ip_network in self.cdn_ip_networks:

                        if ip_address in cdn_ip_network:
                            print(f"IP address {ip_address} is in CDN network: {cdn_ip_network}")
                            self.update_disallowed_target(targets_dict, ip_address)
                            # Using "continue" only returns to the local self.cdn_ip_networks for loop, not the parent
                            # target_list for loop.  Set cdn_ip_found to True so we can check and bail properly.
                            cdn_ip_found = True
                            break

                    if cdn_ip_found:
                        continue

                # At this point, the IP address is legit.
                if is_ipv4_address(ip_address):
                    targets_dict["ipv4_addresses"]["as_list"].add(ip_address)
                elif is_ipv6_address(ip_address):
                    targets_dict["ipv6_addresses"]["as_list"].add(ip_address)
                else:
                    print(f"Unknown IP address type: {ip_address}")

            # Check if it is an IP network.
            elif is_ip_network(target):

                # Convert to a ipaddress.ip_network object.
                ip_network = ipaddress.ip_network(target, strict=False)

                # Ignore private networks if they are not allowed.
                if ip_network.is_private and self.exclude_private_ips:
                    print(f"IP network is private: {target}")
                    self.update_disallowed_target(targets_dict, ip_network)
                    continue

                # IPv4 network.
                if type(ip_network) == ipaddress.IPv4Network:
                    targets_dict["ipv4_networks"]["as_list"].add(target)
                # IPv6 network.
                else:
                    targets_dict["ipv6_networks"]["as_list"].add(target)

            # Check if it is a FQDN with a valid top level domain (TLD).
            # Without the TLD check, it will categorize fat-fingered IP addresses (192.168.1.999) as valid FQDNs just
            # based off allowable characters in a FQDN.
            elif is_valid_fqdn(target) and domain_has_valid_fqdn(target):
                targets_dict["domains"]["as_list"].add(target.strip("."))

            # Not a valid target.
            else:
                # print(f"Invalid target type: {target}")
                targets_dict["invalid_targets"].add(target)

        print("=" * 10)

        # Loop through each category and perform some cleanup maintenance.
        for target_type in ["ipv4_addresses", "ipv4_networks", "ipv6_addresses", "ipv6_networks", "domains"]:

            temp_list_of_objects = targets_dict[target_type]["as_list"]

            # Sort within each individual target type: "ipv4_addresses", "ipv4_networks", "ipv6_addresses",
            # "ipv6_networks", "domains"
            if self.sort_targets:
                try:
                    # Calling sorted() returns temp_list as a list.
                    temp_list_of_objects = sorted(temp_list_of_objects)
                except Exception as e:
                    print(f"Exception sorting targets in '{target_type}': {e}")

            # Convert objects to strings.
            temp_list_of_strings = [str(obj) for obj in temp_list_of_objects]

            # Re-assign to the coresponding keys.
            targets_dict[target_type]["as_list"] = temp_list_of_strings
            targets_dict[target_type]["as_csv"] = ",".join(temp_list_of_strings)
            targets_dict[target_type]["as_nmap"] = " ".join(temp_list_of_strings)

            # For IP networks, calculate the number of targets in the network.  At this point in the logic,
            # ip_network has been vetted to be either an IPv4 or IPv6 network (see is_ip_network() function).
            if target_type in ["ipv4_networks", "ipv6_networks"]:

                for ip_network in temp_list_of_objects:

                    ip_network = ipaddress.ip_network(ip_network, strict=False)

                    # IPv4 network.  Only need to check the network type here.
                    if type(ip_network) == ipaddress.IPv4Network:
                        targets_in_ip_subnet = ip_network.num_addresses
                    # IPv6 network.  No need to check the network type here, if it is not IPv4, it has to be IPv6.
                    else:
                        targets_in_ip_subnet = ipaddress.IPv6Network(ip_network).num_addresses

                    targets_dict[target_type]["total"] += targets_in_ip_subnet
                    targets_dict["total"] += targets_in_ip_subnet

            else:
                targets_dict[target_type]["total"] = len(temp_list_of_strings)
                targets_dict["total"] += len(temp_list_of_strings)

            # Extend array with target_type's list.  This is a kind of soft sort by putting them in order of the
            # target_type for loop ("ipv4_addresses", "ipv4_networks", "ipv6_addresses", "ipv6_networks", "domains").
            # The traditional sorted() will not work with the various object types.
            targets_dict["as_list"].extend(temp_list_of_strings)

        # Convert to a csv delimited string.
        targets_dict["as_csv"] = ",".join(targets_dict["as_list"])

        # Convert to a space-delimited string.
        targets_dict["as_nmap"] = " ".join(targets_dict["as_list"])

        # Housekeeping for invalid_targets.
        # Convert from set to list.
        targets_dict["invalid_targets"] = list(targets_dict["invalid_targets"])
        targets_dict["invalid_targets_total"] = len(targets_dict["invalid_targets"])

        # Convert invalid_targets objects to strings.
        targets_dict["invalid_targets"] = [str(obj) for obj in targets_dict["invalid_targets"]]

        # Housekeeping for disallowed_targets.
        # Convert from set to list.
        targets_dict["disallowed_targets"] = list(targets_dict["disallowed_targets"])
        targets_dict["disallowed_targets_total"] = len(targets_dict["disallowed_targets"])

        # Convert disallowed_targets objects to strings.
        targets_dict["disallowed_targets"] = [str(obj) for obj in targets_dict["disallowed_targets"]]

        # At this stage, all the values in invalid_targets and disallowed_targets are strings.  Thus, sorting may not be
        # perfect looking, but we can do it anyway.
        if self.sort_targets:
            for target_type in ["invalid_targets", "disallowed_targets"]:
                try:
                    targets_dict[target_type].sort()
                except Exception as e:
                    print(f"Exception sorting targets in '{target_type}': {e}")

        # Write output to disk.
        if self.write_to_disk:
            print("Writing targets_dict to disk")
            with open("targets_dict.json", "w") as fh:
                fh.write(json.dumps(targets_dict, indent=4))

        return targets_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Extract IPs and domains from a string or file.")
    parser.add_argument(
        "-d",
        "--delimiter",
        dest="delimiter",
        action="store",
        default="",
        type=str,
        help="Delimiter to find targets using Python's split().",
    )
    parser.add_argument(
        "-i",
        "--exclude-cdn-ip-networks",
        dest="exclude_cdn_ip_networks",
        action="store_true",
        required=False,
        default=False,
        help="Exclude IPs belonging to CDNs like AWS' CloudFront, Cloudflare, etc.",
    )
    parser.add_argument(
        "-n",
        "--retrieve-latest-cdn-data",
        dest="retrieve_new_cdn_ip_data",
        action="store_true",
        required=False,
        default=False,
        help=(
            "Retrieve new CDN IP data from AWS' CloudFront, Cloudflare, etc. instead of utilizing previous data stored "
            "on local files."
        ),
    )
    parser.add_argument(
        "-p",
        "--exclude-private-ips",
        dest="exclude_private_ips",
        action="store_true",
        default=False,
        help="Exclude private RFC1918 IPs (192.168.1.1) and networks (192.168.1.0/24).",
    )
    parser.add_argument("-s", "--sort", dest="sort_targets", action="store_true", default=False, help="Sort targets")
    parser.add_argument(
        "-w",
        "--write-to-disk",
        dest="write_to_disk",
        action="store_true",
        required=False,
        default=False,
        help="Write the targets_dict to disk.",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--targets-file", dest="targets_file", action="store", help="File containing potential targets."
    )
    group.add_argument(
        "-t",
        "--target-string",
        dest="targets_string",
        action="store",
        help="String of targets '8.8.8.8 4.4.4.4 scanme.nmap.org ::ffff:c0a8:101'",
    )

    args = parser.parse_args()

    if args.targets_file and not os.path.exists(args.targets_file):
        print("[!] Specify a valid file containing targets.")
        sys.exit(1)

    # args.targets_string = "rackspace.com rackspace.comm 100.12.43.55 1.2.3.4 1.5.4.8 22.22.224.24 2.2.2.2 127.0.0.1 2001:978:1:2::d  7.7.7.0/24  4.4.4.4  . : % ^ 2.2.3.)  1.84.5.2555 224.0.1.10 169.254.169.254 2.2.2.3 2.2.2.4 13.228.69.5 2405:b500:ffff:ffff:ffff:ffff:ffff:fff3 103.31.4.105"

    te = TargetExtractor(**vars(args))
    targets_dict = te.targets_dict

    print(json.dumps(targets_dict, indent=4))
