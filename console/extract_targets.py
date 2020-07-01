"""Extracts FQDNs, IPv4, and IPv6 addresses from a string or file."""

# Standard Python libraries.
import argparse
import ipaddress
import os
import pprint
import sys

# Third party Python libraries.


# Custom Python libraries.
import fqdn


class TargetExtractor:
    def __init__(self, targets_string=None, targets_file=None, private_ips_allowed=False, sort_targets=False):
        self.targets_string = str(targets_string).strip()
        self.targets_file = targets_file
        self.private_ips_allowed = private_ips_allowed
        self.sort_targets = sort_targets

        # Read targets from file as string.
        if self.targets_file:
            with open(self.targets_file, "r") as fh:
                self.targets_string = fh.read().strip()

        self.targets_dict = self.extract_targets(self.targets_string)

    def is_ip_address(self, ip):
        """Takes an IP address returns True/False if it is a valid IPv4 or IPv6 address."""

        ip = str(ip)

        try:
            ipaddress.ip_address(ip)
            return True

        except ValueError:
            return False

    def is_ip_network(self, address, strict=False):
        """Takes an address returns True/False if it is a valid network."""

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
        """Takes an IP address and returns True/False if it is a valid IPv4 address."""

        ip = str(ip)

        try:
            if ipaddress.ip_address(ip).version == 4:
                return True

            else:
                return False

        except ValueError as e:
            print(f"{e}")

    def is_ipv6_address(self, ip):
        """Takes an IP address and returns True/False if it is a valid IPv6 address."""

        ip = str(ip)

        try:
            if ipaddress.ip_address(ip).version == 6:
                return True

            else:
                return False

        except ValueError as e:
            print(f"{e}")

    def update_disallowed_target(self, targets_dict, target):
        """Update disallowed target list and count."""

        targets_dict["disallowed_targets"].append(str(target))

    def extract_targets(self, targets_string):
        """Extracts valid IPv4 IP addresses from a string."""

        # Dictionary to track valid and invalid targets.
        # fmt:off
        targets_dict = {
            "ip_addresses": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "ip_networks": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
            },
            "domains": {
                "as_list": [],
                "as_csv": "",
                "as_nmap": "",
                "total": 0,
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
        target_list = targets_string.split()

        for target in target_list:

            # Convert to a ipaddress object if it is an IP address.
            if self.is_ip_address(target):

                ip_address = ipaddress.ip_address(target)

                # Ensure they are not RFC1918.
                # Cloud metadata IPs are covered under this as well: 169.254.169.254
                if ip_address.is_private and not self.private_ips_allowed:
                    print(f"IP address is a private IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                elif ip_address.is_multicast:
                    print(f"IP address is a multicast IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                elif ip_address.is_loopback:
                    print(f"IP address is a loopback IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                elif ip_address.is_link_local:
                    print(f"IP address is a link local IP: {ip_address}")
                    self.update_disallowed_target(targets_dict, ip_address)
                    continue

                # Double check and make sure IP is a public (global) IP if private IPs are not allowed.
                if not ip_address.is_global and not self.private_ips_allowed:
                    print(f"IP address is not a public IP: {ip_address}")
                    continue

                if self.is_ipv4_address(ip_address):
                    targets_dict["ip_addresses"]["as_list"].append(ip_address)
                elif self.is_ipv6_address(ip_address):
                    targets_dict["ip_addresses"]["as_list"].append(ip_address)
                else:
                    print(f"Unknown IP address type: {ip_address}")

            # Check if it is an IP network.
            elif self.is_ip_network(target):

                # Ignore private networks if they are not allowed.
                if not self.private_ips_allowed and ipaddress.ip_network(target).is_private:
                    print(f"IP network is private and private networks are not allowed: {target}")
                    continue

                targets_dict["ip_networks"]["as_list"].append(target)

            # Check if it is a FQDN.
            elif self.is_valid_fqdn(target):
                targets_dict["domains"]["as_list"].append(target)

            # Not a valid target.
            else:
                print(f"Invalid target type: {target}")
                targets_dict["invalid_targets"].append(target)

        print("=" * 10)

        for target_type in ["ip_addresses", "ip_networks", "domains"]:

            # Remove duplicates.
            targets_dict[target_type]["as_list"] = list(set(targets_dict[target_type]["as_list"]))

            temp_list = []

            # Standardize object type to string.
            for target in targets_dict[target_type]["as_list"]:
                temp_list.append(str(target))

            # Sort within each individual target type: "ip_addresses", "ip_networks", or "domains"
            if self.sort_targets:
                try:
                    temp_list.sort()
                except Exception as e:
                    print(f"Exception sorting targets in '{target_type}': {e}")

            targets_dict[target_type]["as_list"] = temp_list
            targets_dict[target_type]["as_csv"] = ",".join(temp_list)
            targets_dict[target_type]["as_nmap"] = " ".join(temp_list)

            targets_dict[target_type]["total"] = len(temp_list)

            # Extend array with target_type's list.  If requested, will sort later.
            targets_dict["as_list"].extend(temp_list)

            targets_dict["total"] += len(temp_list)

        # Sort for combined "as_list" targets.
        if self.sort_targets:
            try:
                targets_dict["as_list"].sort()
            except Exception as e:
                print(f"Exception sorting targets: {e}")

        # Remove invalid duplicate targets.
        targets_dict["invalid_targets"] = list(set(targets_dict["invalid_targets"]))
        targets_dict["invalid_targets_total"] = len(targets_dict["invalid_targets"])

        # Remove disallowed duplicate targets.
        targets_dict["disallowed_targets"] = list(set(targets_dict["disallowed_targets"]))
        targets_dict["disallowed_targets_total"] = len(targets_dict["disallowed_targets"])

        targets_dict["as_csv"] = ",".join(targets_dict["as_list"])
        targets_dict["as_nmap"] = " ".join(targets_dict["as_list"])

        return targets_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Extract IPs and domains from a string or file.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", dest="targets_file", action="store", help="File with targets.")
    parser.add_argument(
        "-p",
        dest="private_ips_allowed",
        action="store_true",
        default=False,
        help="Private RFC1918 IPs (192.168.1.1) and networks (192.168.1.0/24) are allowed.",
    )
    parser.add_argument("-s", dest="sort_targets", action="store_true", default=False, help="Sort targets")
    group.add_argument(
        "-t",
        dest="targets_string",
        action="store",
        help="String of targets '8.8.8.8 4.4.4.4 scanme.nmap.org ::ffff:c0a8:101'",
    )

    args = parser.parse_args()

    if args.targets_file and not os.path.exists(args.targets_file):
        print("[!] Specify a valid file containing targets.")
        sys.exit(1)

    # args.targets_string = "100.12.43.55 1.2.3.4 1.5.4.8 22.22.224.24 2.2.2.2 127.0.0.1 2001:978:1:2::d  7.7.7.0/24  4.4.4.4  . : % ^ 2.2.3.)  1.84.5.2555 224.0.1.10 169.254.169.254 2.2.2.3 2.2.2.4"

    te = TargetExtractor(**vars(args))
    targets_dict = te.targets_dict

    pprint.pprint(targets_dict)
