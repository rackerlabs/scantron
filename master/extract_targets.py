"""Extracts IPv4 addresses and FQDNs from a string or file."""

# Standard Python libraries.
import argparse
import ipaddress
import os
import pprint

# import re
import sys

# Third party Python libraries.


# Custom Python libraries.
import fqdn


class TargetExtractor:
    def __init__(self, targets_string=None, targets_file=None, private_ips_allowed=False):
        self.targets_string = str(targets_string).strip()
        self.targets_file = targets_file
        self.private_ips_allowed = private_ips_allowed

        # Read targets from file as string.
        if self.targets_file:
            with open(self.targets_file, "r") as fh:
                self.targets_string = fh.read().strip()

        self.targets_dict = self.extract_targets(self.targets_string)

    def is_ip_address(self, ip):
        """Takes an IP address returns true or false if it is a valid IPv4 or IPv6 address."""

        ip = str(ip)

        try:
            ipaddress.ip_address(ip)
            return True

        except ValueError:
            return False

    def is_ip_network(self, address, strict=False):
        """Takes an address returns true or false if it is a valid network."""

        address = str(address)

        try:
            ipaddress.ip_network(address, strict)
            return True

        except ValueError:
            return False

    def is_valid_fqdn(self, domain):
        """Test if a provided domain is a valid FQDN."""

        is_valid_fqdn = fqdn.FQDN(domain).is_valid

        return is_valid_fqdn

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

    def is_ipv4_address(self, ip):
        """Takes an IP address returns true or false if it is a valid IPv4."""

        ip = str(ip)

        try:
            if ipaddress.ip_address(ip).version == 4:
                return True

            elif ipaddress.ip_address(ip).version == 6:
                return False

        except ValueError as e:
            print(f"{e}")

    def update_disallowed_target(self, master_targets_dict, target):
        """Update disallowed target list and count."""

        master_targets_dict["disallowed_targets"].append(str(target))
        master_targets_dict["disallowed_targets_total"] += 1

    def extract_targets(self, targets_string):
        """Extracts valid IPv4 IP addresses from a string."""

        # Dictionary to track valid and invalid targets.
        # fmt:off
        master_targets_dict = {
            "ip_addresses": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0
            },
            "ip_networks": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0
            },
            "domains": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0
            },
            "invalid_targets": [],
            "invalid_targets_total": 0,
            "disallowed_targets": [],
            "disallowed_targets_total": 0,
            "as_list": [],
            "as_csv": "",
            "as_nmap": "",
            "total": 0,
        }
        # fmt:on

        # Split on spaces.
        ip_addresses_list = targets_string.split()

        for target in ip_addresses_list:

            # print(ip)

            # Only allow certain characters: . : and 0-9
            # Allows IPv6, even though they are not allowed later in the code.  Allowed in case IPv6 addresses
            # are allowed in the future.
            # match = re.match(r"[0-9a-f\.\:]", ip, re.IGNORECASE)

            # if not match:
            #     print(f"Invalid character detected in IP: {ip}")
            #     continue

            # Convert to a ipaddress object if it is an IP address.
            if self.is_ip_address(target):

                ip_address = ipaddress.ip_address(target)

                # Ensure they are not RFC1918.
                # Cloud metadata IPs are covered under this as well: 169.254.169.254
                if ip_address.is_private and not self.private_ips_allowed:
                    print(f"IP address is a private IP: {ip_address}")
                    self.update_disallowed_target(master_targets_dict, ip_address)
                    continue

                elif ip_address.is_multicast:
                    print(f"IP address is a multicast IP: {ip_address}")
                    self.update_disallowed_target(master_targets_dict, ip_address)
                    continue

                elif ip_address.is_loopback:
                    print(f"IP address is a loopback IP: {ip_address}")
                    self.update_disallowed_target(master_targets_dict, ip_address)
                    continue

                elif ip_address.is_link_local:
                    print(f"IP address is a link local IP: {ip_address}")
                    self.update_disallowed_target(master_targets_dict, ip_address)
                    continue

                # Metadata URLs.
                # elif str(ip_address) in ["169.254.169.254",]:
                #     print(f"IP address is a cloud metadata IP: {ip_address}")

                # Double check and make sure IP is a public (global) IP if private IPs are not allowed.
                if not ip_address.is_global and not self.private_ips_allowed:
                    print(f"IP address is not a public IP: {ip_address}")
                    continue

                if self.is_ipv4_address(ip_address):
                    # print(ip_address)
                    master_targets_dict["ip_addresses"]["as_list"].append(ip_address)
                else:
                    print(f"IPv6 IP addresses are not allowed: {ip_address}")

            # Check if it is an IP network.
            elif self.is_ip_network(target):
                master_targets_dict["ip_networks"]["as_list"].append(target)

            # Check if it is a FQDN.
            elif self.is_valid_fqdn(target):
                master_targets_dict["domains"]["as_list"].append(target)

            # Not a valid target.
            else:
                print(f"Invalid target type: {target}")
                master_targets_dict["invalid_targets"].append(target)
                master_targets_dict["invalid_targets_total"] += 1

        print("=" * 10)

        for i in ["ip_addresses", "ip_networks", "domains"]:

            master_targets_dict[i]["as_list"].sort()

            temp_list = []

            for j in master_targets_dict[i]["as_list"]:
                temp_list.append(str(j))

            master_targets_dict["as_list"].extend(temp_list)
            master_targets_dict[i]["as_csv"] = ",".join(temp_list)
            master_targets_dict[i]["as_nmap"] = " ".join(temp_list)

            master_targets_dict[i]["total"] = len(temp_list)
            master_targets_dict["total"] += len(temp_list)

        temp_list = []
        for k in master_targets_dict["as_list"]:
            temp_list.append(str(k))

        master_targets_dict["as_csv"] = ",".join(temp_list)
        master_targets_dict["as_nmap"] = " ".join(temp_list)

        return master_targets_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Extract IPs and domains from a string or file.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", dest="targets_file", action="store", help="File with targets.")
    parser.add_argument(
        "-p",
        dest="private_ips_allowed",
        action="store_true",
        default=False,
        help="Private RFC1918 IPs allowed (192.168.1.1)",
    )
    group.add_argument("-t", dest="targets_string", action="store", help="String of targets '8.8.8.8 4.4.4.4'")

    args = parser.parse_args()

    if args.targets_file and not os.path.exists(args.targets_file):
        print("[!] Specify a valid file containing targets.")
        sys.exit(1)

    # args.targets_string = "100.12.43.55 1.2.3.4 1.5.4.8 22.22.224.24 2.2.2.2 127.0.0.1 2001:978:1:2::d  7.7.7.0/24  4.4.4.4  . : % ^ 2.2.3.)  1.84.5.2555 224.0.1.10 169.254.169.254 2.2.2.3 2.2.2.4"

    te = TargetExtractor(**vars(args))
    master_targets_dict = te.targets_dict

    pprint.pprint(master_targets_dict)
