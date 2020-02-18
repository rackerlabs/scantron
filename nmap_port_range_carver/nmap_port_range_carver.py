#!/usr/bin/env python

# Standard Python libraries.
import argparse

# Third party Python libraries.


# Custom Python libraries.


# BASH command to generate nmap_top_ports_PROTOCOL.txt files.
r"""
egrep /tcp /usr/share/nmap/nmap-services | sort -r -k3 | sed 's/[\t ]/,/g' \
    | cut -d "," -f 2 | cut -f 1 -d "/" > nmap_top_ports_tcp.txt
egrep /udp /usr/share/nmap/nmap-services | sort -r -k3 | sed 's/[\t ]/,/g' \
    | cut -d "," -f 2 | cut -f 1 -d "/" > nmap_top_ports_udp.txt
"""


def main(start_rank, end_rank, protocol="tcp"):

    if protocol == "tcp":
        port_file = "nmap_top_ports_tcp.txt"

    elif protocol == "udp":
        port_file = "nmap_top_ports_udp.txt"

    else:
        print("This should never be reached.")
        exit()

    # Build list of port ranks.
    port_list = []

    with open(port_file, "r") as fh:
        for index, port in enumerate(fh):
            port_list.append(port.strip())

    # Don't subtract one from end_rank to include actual rank.
    # Creates a list of strings, will covert to list of ints later.
    port_rank_list_temp = port_list[(start_rank - 1) : end_rank]  # noqa
    port_rank_csv = ",".join(port_rank_list_temp)

    port_rank_list = []
    for rank in port_rank_list_temp:
        port_rank_list.append(int(rank))

    print(f"port_rank_list: {port_rank_list}")
    print(f"port_rank_csv: {port_rank_csv}")

    # fmt: off
    port_rank_dict = {
        "port_rank_list": port_rank_list,
        "port_rank_csv": port_rank_csv,
    }
    # fmt: on

    return port_rank_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "-s", dest="start_rank", action="store", type=int, required=True, help="Port rank to start at.  Minimum: 1"
    )
    parser.add_argument(
        "-e", dest="end_rank", action="store", type=int, required=True, help="Port rank to end at.  Maximum: 8309"
    )
    parser.add_argument(
        "-p",
        dest="protocol",
        action="store",
        required=False,
        default="tcp",
        help="Specify tcp or udp protocol.  Default: tcp",
    )

    args = parser.parse_args()

    args.protocol = args.protocol.lower()

    if args.protocol not in ["tcp", "udp"]:
        print("Protocol must be 'tcp' or 'udp'")
        exit()

    if args.end_rank < args.start_rank:
        print("Start rank must be less than (<) end rank.")
        exit()

    if args.start_rank not in range(1, 8310):
        print("Port start rank must be 1-8309 inclusive")
        exit()

    if args.end_rank not in range(1, 8310):
        print("Port end rank must be 1-8309 inclusive")
        exit()

    main(**vars(args))
