# Carve out top TCP/UDP ranked ports from nmap according to the nmap-services file

A standalone script to carve out a range of the top TCP/UDP ports according to the `nmap-services` file.  This is useful
when:

1. You want to scan a subset of the ports specified in `--top-ports`, say the 10th through 20th top TCP ports, but not
the 1st or 9th ports.

2. You want the 1337th ranked TCP port.

3. You want to utilize nmap to scan **both** TCP and UDP, but not scan the same number of top ports.

    This works and will scan the top 10 ports for BOTH TCP and UDP

    ```bash
    nmap --top-ports 10 -sU -sT <TARGET>
    ```

    but you can't only scan the top 20 TCP and top 10 UDP ports using `--top-ports`.

## Installation

```bash
git clone https://github.com/rackerlabs/scantron.git
cd scantron/nmap_port_range_carver
virtualenv -p python3 .venv  # If using a virtual environment.
source .venv/bin/activate  # If using a virtual environment.
```

## Command Line Usage

Script switches

```bash
python nmap_port_range_carver.py -h
```

Retrieve TCP ports ranked 10 through 20:

```bash
$ python nmap_port_range_carver.py -s 10 -e 20
port_rank_list: [139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900]
port_rank_csv: 139,143,53,135,3306,8080,1723,111,995,993,5900
```

Retrieve 1,337th ranked TCP port:

```bash
$ python nmap_port_range_carver.py -s 1337 -e 1337
port_rank_list: [7010]
port_rank_csv: 7010
```

Retrieve UDP ports ranked 50 through 60:

```bash
$ python nmap_port_range_carver.py -s 50 -e 60 -p udp
port_rank_list: [1027, 177, 1719, 427, 497, 4444, 1023, 65024, 19, 9, 49193]
port_rank_csv: 1027,177,1719,427,497,4444,1023,65024,19,9,49193
```

## Python Import Usage

If used as a Python module, it returns a dictionary with a keys for a Python list and CSV string:

```python
import nmap_port_range_carver
tcp_ports_range_10_20 = nmap_port_range_carver.main(start_rank=10, end_rank=20, protocol="tcp")
print(tcp_ports_range_10_20)
```

```json
{
    "port_rank_list": [139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900],
    "port_rank_csv": "139,143,53,135,3306,8080,1723,111,995,993,5900"
}
```

## Generate top ports files from nmap's nmap-services

> Note: The `nmap-services` file only contains the top 8309 ports.

These files are already provided, but here are the commands to generate them.

```bash
egrep /tcp /usr/share/nmap/nmap-services | sort -r -k3 | sed 's/[\t ]/,/g' \
    | cut -d "," -f 2 | cut -f 1 -d "/" > nmap_top_ports_tcp.txt
egrep /udp /usr/share/nmap/nmap-services | sort -r -k3 | sed 's/[\t ]/,/g' \
    | cut -d "," -f 2 | cut -f 1 -d "/" > nmap_top_ports_udp.txt
```
