# Standard Python libraries.
import datetime
import ipaddress
import json
import sys
import time
import urllib3

# Third party Python libraries.
import requests
from requests_toolbelt.utils import dump

# Custom Python libraries.


__version__ = "1.0.7"


def debug_requests_response(response):
    """Provide debug print info for a requests response object."""

    data = dump.dump_all(response)
    print(data.decode("utf-8"))


def get_timestamp():
    """Generates a timestamp."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)

    return timestamp


def get_iso_8601_timestamp_no_second():
    """Generates an ISO 8601 standardized timestamp.
    https://en.wikipedia.org/wiki/ISO_8601"""

    now = time.localtime()
    timestamp = time.strftime("%Y-%m-%dT%H:%M", now)

    return timestamp


def expand_range_of_ips(start_ip, end_ip):
    """Takes an IP range and returns all the IPs in that range.
    # http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
    """

    ip_range = []

    if (ipaddress.ip_address(start_ip).version == 6) or (ipaddress.ip_address(end_ip).version == 6):
        print("IPv6 IP range not supported in this function: {} - {}".format(start_ip, end_ip))
        return ip_range

    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range


def http_status_code(http_code):
    """Contains a database of all known HTTP status codes and their corresponding plain text description.  For use in
    both program output as well as parsing for specific issue types.

    Args:
        http_code (int): A number containing the HTTP status code to lookup

    Returns:
        string: Returns a description of the status code.
    """

    http_codes = {
        200: "OK",
        201: "OK: Created",
        202: "OK: Accepted",
        203: "OK: Non-Authoritative Information",
        204: "OK: No Content",
        205: "OK: Reset Content",
        206: "OK: Partial Content",
        207: "OK: Multi-Status",
        208: "OK: Already Reported",
        226: "OK: IM Used",
        300: "Redirected: Multiple Choices",
        301: "Redirected: Moved Permanently",
        302: "Redirected: Found",
        303: "Redirected: See Other",
        304: "Redirected: Not Modified",
        305: "Redirected: Use Proxy",
        306: "Redirected: Switch Proxy",
        307: "Redirected: Temporary Redirect",
        308: "Redirected: Permanent Redirect",
        400: "Client Error: Bad Request",
        401: "Client Error: Unauthorized",
        402: "Client Error: Payment Required",
        403: "Client Error: Forbidden",
        404: "Client Error: Not Found",
        405: "Client Error: Method Not Allowed",
        406: "Client Error: Not Acceptable",
        407: "Client Error: Proxy Authentication Required",
        408: "Client Error: Request Timeout",
        409: "Client Error: Conflict",
        410: "Client Error: Gone",
        411: "Client Error: Length Required",
        412: "Client Error: Precondition Failled",
        413: "Client Error: Payload Too Large",
        414: "Client Error: URI Too Large",
        415: "Client Error: Unsupported Media Type",
        416: "Client Error: Range Not Satisfiable",
        417: "Client Error: Expectation Failed",
        418: "Client Error: I'm a teapot",
        421: "Client Error: Misdirected Request",
        422: "Client Error: Un-processable Entity",
        423: "Client Error: Locked",
        424: "Client Error: Failed Dependency",
        426: "Client Error: Upgrade Required",
        428: "Client Error: Precondition Required",
        429: "Client Error: Too Many Requests",
        431: "Client Error: Request Header Fields Too Large",
        440: "Client Error: Login Time-Out",
        444: "Client Error: No Response",
        449: "Client Error: Retry With",
        451: "Client Error: Unavailable For Legal Reasons",
        495: "Client Error: SSL Certificate Error",
        496: "Client Error: SSL Certificate Required",
        497: "Client Error: HTTP Request Sent to HTTPS Port",
        499: "Client Error: Client Closed Request",
        500: "Server Error: Internal Server Error",
        501: "Server Error: Not Implemented",
        502: "Server Error: Bad Gateway",
        503: "Server Error: Service Unavailable",
        504: "Server Error: Gateway Timeout",
        505: "Server Error: HTTP Version Not Supported",
        507: "Server Error: Insufficient Storage",
        508: "Server Error: Loop Detected",
        510: "Server Error: Not Extended",
        511: "Server Error: Network Authentication Required",
        520: "Server Error: Unknown Error when connecting to server behind load balancer",
        521: "Server Error: Web Server behind load balancer is down",
        522: "Server Error: Connection Timed Out to server behind load balancer",
        523: "Server Error: Server behind load balancer is unreachable",
        524: "Server Error: TCP handshake with server behind load balancer completed but timed out",
        525: "Server Error: Load balancer could not negotiate a SSL/TLS handshake with server behind load balancer",
        526: "Server Error: Server behind load balancer returned invalid SSL/TLS cert to load balancer",
        527: "Server Error: Load balancer request timed out/failed after WAN connection was established to origin server",
    }

    http_status = http_codes.get(http_code, "NA")

    return http_status


class ScantronClient:
    def __init__(self, secrets_file_location="./scantron_api_secrets.json", **kwargs):
        """Initialize a Scantron client."""

        SECRETS = {}

        try:
            with open(secrets_file_location) as config_file:
                SECRETS = json.loads(config_file.read())
        except OSError:
            print(f"Error: {secrets_file_location} does not exist.  Exiting...")
            sys.exit(1)

        # Ensure key/values exist in secrets.json.
        try:
            self.host = SECRETS["scantron"]["host"]
            self.port = SECRETS["scantron"]["port"]
            self.token = SECRETS["scantron"]["token"]

        except KeyError:
            print(f"Error reading key-values in {secrets_file_location} file.  Exiting...")
            sys.exit(1)

        # Build BASE_URL.
        self.BASE_URL = f"https://{self.host}:{self.port}"

        # Minimize Python requests (and the underlying urllib3 library) logging level.
        # logging.getLogger("requests").setLevel(print)
        # logging.getLogger("urllib3").setLevel(print)

        # Extract User-Agent, default to "scantron-api-client-v(version)".
        self.user_agent = kwargs.get("user_agent", f"scantron-api-client-v{__version__}")

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {self.token}",
            "User-Agent": self.user_agent,
        }

        # Extract timeout, default to 30 seconds.
        self.timeout = kwargs.get("timeout", 30)

        # Extract self_signed, default to True.
        self.api_self_signed = kwargs.get("api_self_signed", True)

        # Extract max attempts, default to 3.
        self.max_attempts = kwargs.get("max_attempts", 3)

        if self.api_self_signed:
            urllib3.disable_warnings()

        self.debug_print = False

    def scantron_api_query(self, endpoint, **kwargs):
        """Executes a properly formatted API call to the Scantron API with the supplied arguments."""

        url = f"{self.BASE_URL}{endpoint}"

        # Set HTTP headers.
        headers = kwargs.get("headers", {})

        if not isinstance(headers, dict):
            raise ValueError("headers keyword passed to scantron_api_query is not a valid dict object")

        # Merge dictionaries.
        # https://treyhunner.com/2016/02/how-to-merge-dictionaries-in-python/
        headers = {**self.headers, **headers}

        # Extract HTTP verb, defaults to GET.
        method = kwargs.get("method", "GET")
        method = method.upper()

        # Extract additional parameters, defaults to an empty dictionary.
        parameters = kwargs.get("params", {})

        if not isinstance(parameters, dict):
            raise ValueError("params keyword passed to scantron_api_query is not a valid dict object")

        # Extract payload.
        payload = kwargs.get("payload", "{}")

        # Used to track number of failed HTTP requests.
        attempts = 0

        while True:
            try:
                if method == "GET":
                    response = requests.get(
                        url,
                        headers=headers,
                        params=parameters,
                        json=payload,
                        verify=(not self.api_self_signed),
                        timeout=self.timeout,
                    )

                    if response.status_code != 200:
                        debug_requests_response(response)

                    break

                elif method == "POST":
                    response = requests.post(
                        url,
                        headers=headers,
                        params=parameters,
                        json=payload,
                        verify=(not self.api_self_signed),
                        timeout=self.timeout,
                    )

                    if response.status_code != 201:
                        debug_requests_response(response)

                    break

                elif method == "PATCH":
                    response = requests.patch(
                        url,
                        headers=headers,
                        params=parameters,
                        json=payload,
                        verify=(not self.api_self_signed),
                        timeout=self.timeout,
                    )

                    if response.status_code != 200:
                        debug_requests_response(response)

                    break

                elif method == "PUT":
                    response = requests.put(
                        url,
                        headers=headers,
                        params=parameters,
                        json=payload,
                        verify=(not self.api_self_signed),
                        timeout=self.timeout,
                    )

                    if response.status_code != 200:
                        debug_requests_response(response)

                    break

                elif method == "DELETE":
                    response = requests.delete(
                        url,
                        headers=headers,
                        params=parameters,
                        json=payload,
                        verify=(not self.api_self_signed),
                        timeout=self.timeout,
                    )

                    if response.status_code != 204:
                        debug_requests_response(response)

                    break

                else:
                    print(f"Invalid HTTP method passed to scantron_api_query: {method}")
                    raise ValueError(f"Invalid HTTP method passed to scantron_api_query: {method}")

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError,
            ):
                attempts += 1
                if self.max_attempts < attempts:
                    print(
                        f"Unable to reach Scantron API after {self.max_attempts} tries.  Consider increasing the timeout."
                    )
                    sys.exit(1)
                else:
                    print("Packet loss when attempting to reach the Scantron API.")

        if self.debug_print:
            debug_requests_response(response)

        return response

    def retrieve_server_time(self):
        """Retrieve the date and time on the server.  Useful when scheduling scans using the API.  Returns a string of
        Django's localtime().isoformat."""

        response = self.scantron_api_query("/api/server_time")

        if response.status_code == 200:
            server_time = response.json()["server_time"]

        return server_time

    # Scan Results
    ##############
    def retrieve_scan_results(self, scan_id, file_type, write_to_disk=False, **kwargs):
        """Returns a text blob of the scan results if they actually exist.  For .json files, the requests .json()
        method is called to return a Python dictionary object."""

        scan_results = None

        file_type = file_type.lower()
        file_name = f"scan_results_{scan_id}.{file_type}"

        if file_type not in ["nmap", "xml", "json", "pooled"]:
            print(f"Not a valid file type: {file_type}")

        else:
            response = self.scantron_api_query(f"/results/{scan_id}?file_type={file_type}", **kwargs)

            if response.status_code == 200 and file_type in ["nmap", "xml"]:
                scan_results = response.text

                if write_to_disk:
                    with open(file_name, "w") as fh:
                        fh.write(scan_results)

            elif response.status_code == 200 and file_type in ["json", "pooled"]:
                try:
                    scan_results = response.json()

                    if write_to_disk:
                        with open(file_name, "w") as fh:
                            json.dump(scan_results, fh)

                except Exception as e:
                    print(f"Exception decoding json for scan ID {scan_id}: {e}")

        return scan_results

    # CONFIGURATION
    ###############
    # Configuration - CRUD functions.
    def retrieve_configuration(self):
        """Retrieve configuration.  Hard-coded to a configuration ID of 1."""
        return self.scantron_api_query("/api/configuration/1", method="GET")

    def update_configuration(self, payload):
        """Update configuration.  Hard-coded to a configuration ID of 1."""
        return self.scantron_api_query("/api/configuration/1", method="PATCH", payload=payload)

    # ENGINES
    #########
    # Engines - CRUD functions.
    def create_engine(self):
        """Create a scan command."""
        print("no create function, an Engine is created when a Django User is created.")
        return None

    def retrieve_engine(self, engine_id):
        """Retrieve an engine."""
        return self.scantron_api_query(f"/api/engines/{engine_id}", method="GET")

    def update_engine(self, engine_id, payload):
        """Update an engine."""
        return self.scantron_api_query(f"/api/engines/{engine_id}", method="PATCH", payload=payload)

    def delete_engine(self, engine_id):
        """Delete an engine."""
        return self.scantron_api_query(f"/api/engines/{engine_id}", method="DELETE")

    # Engines - Miscellaneous functions.
    def retrieve_engines(self):
        """Retrieve information for all the engines."""
        return self.scantron_api_query("/api/engines").json()

    def retrieve_engine_id_from_engine_name(self, engine_name):
        """Retrieve the engine ID, given an engine name."""

        engines = self.retrieve_engines()

        engine_id = None

        for engine in engines:
            if engine["scan_engine"].lower() == engine_name.lower():
                engine_id = engine["id"]

        return engine_id

    # GLOBALLY EXCLUDED TARGETS
    ###########################
    # Globally Excluded Targets - CRUD functions.
    def create_globally_excluded_target(self, payload):
        """Create a globally excluded target."""
        return self.scantron_api_query("/api/globally_excluded_targets", method="POST", payload=payload)

    def retrieve_globally_excluded_target(self, globally_excluded_target_id):
        """Retrieve globally excluded target."""
        return self.scantron_api_query(
            f"/api/globally_excluded_targets/{globally_excluded_target_id}", method="GET"
        ).json()

    def update_globally_excluded_target(self, globally_excluded_target_id, payload):
        """Update globally excluded target for specific globally excluded target ID."""
        return self.scantron_api_query(
            f"/api/globally_excluded_targets/{globally_excluded_target_id}", method="PATCH", payload=payload
        )

    def delete_globally_excluded_target(self, globally_excluded_target_id):
        """Delete a globally excluded target."""
        return self.scantron_api_query(f"/api/globally_excluded_targets/{globally_excluded_target_id}", method="DELETE")

    # Globally Excluded Targets- Miscellaneous functions.
    def retrieve_globally_excluded_targets(self):
        """Retrieve information for all the globally excluded targets."""
        return self.scantron_api_query("/api/globally_excluded_targets").json()

    # SCAN COMMANDS
    ###############
    # Scan Commands - CRUD functions.
    def create_scan_command(self, payload):
        """Create a scan command."""
        return self.scantron_api_query("/api/scan_commands", method="POST", payload=payload)

    def retrieve_scan_command(self, scan_command_id):
        """Retrieve scan command."""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="GET").json()

    def update_scan_command(self, scan_command_id, payload):
        """Update scan command for specific scan command ID."""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="PATCH", payload=payload)

    def delete_scan_command(self, scan_command_id):
        """Delete a scan."""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="DELETE")

    # Scan Commands - Miscellaneous functions.
    def retrieve_scan_commands(self):
        """Retrieve information for all the scan commands."""
        return self.scantron_api_query("/api/scan_commands").json()

    def retrieve_scan_command_id_from_scan_command_name(self, scan_command_name):
        """Retrieve the scan command ID, given a scan command name."""

        scan_commands = self.retrieve_scan_commands()

        scan_command_id = None

        for scan_command in scan_commands:
            if scan_command["scan_command_name"].lower() == scan_command_name.lower():
                scan_command_id = scan_command["id"]

        return scan_command_id

    # SCANS
    #######
    # Scans - CRUD functions.
    def create_scan(self, payload):
        """Create a scan."""
        return self.scantron_api_query("/api/scans", method="POST", payload=payload)

    def retrieve_scan(self, scan_id):
        """Retrieve a scan."""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="GET")

    def update_scan(self, scan_id, payload):
        """Update scan for specific scan ID."""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="PATCH", payload=payload)

    def delete_scan(self, scan_id):
        """Delete a scan."""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="DELETE")

    # Scans - Miscellaneous functions.
    def retrieve_scans(self):
        """Retrieve information for all the scans."""
        return self.scantron_api_query("/api/scans").json()

    # SCHEDULED SCANS
    #################
    def retrieve_scheduled_scan(self, scheduled_scan_id):
        """Retrieve a scheduled scan."""
        return self.scantron_api_query(f"/api/scheduled_scans/{scheduled_scan_id}", method="GET")

    # Scheduled Scans - Miscellaneous functions.
    def retrieve_scheduled_scans(self):
        """Retrieve information for all scheduled scans."""
        return self.scantron_api_query("/api/scheduled_scans").json()

    # SITES
    #######
    # Sites - CRUD functions.
    def create_site(self, payload):
        """Create a site."""
        return self.scantron_api_query("/api/sites", method="POST", payload=payload)

    def retrieve_site(self, site_id):
        """Retrieve a site."""
        return self.scantron_api_query(f"/api/sites/{site_id}", method="GET")

    def update_site(self, site_id, payload):
        """Update a site."""
        return self.scantron_api_query(f"/api/sites/{site_id}", method="PATCH", payload=payload)

    def delete_site(self, site_id):
        """Delete a site."""
        return self.scantron_api_query(f"/api/sites/{site_id}", method="DELETE")

    # Sites - Miscellaneous functions.
    def retrieve_sites(self):
        """Retrieve information for all the sites."""
        return self.scantron_api_query("/api/sites").json()

    def retrieve_site_id_from_site_name(self, site_name):
        """Retrieve the site ID, given a site name."""

        sites_info = self.retrieve_sites()

        site_id = None

        for site in sites_info:
            if site["site_name"].lower() == site_name.lower():
                site_id = site["id"]

        return site_id

    # ENGINE POOLS
    ###############
    # Engine Pools - CRUD functions.
    def create_engine_pool(self, payload):
        """Create an engine pool."""
        return self.scantron_api_query("/api/engine_pools", method="POST", payload=payload)

    def retrieve_engine_pool(self, engine_pool_id):
        """Retrieve engine pool."""
        return self.scantron_api_query(f"/api/engine_pools/{engine_pool_id}", method="GET").json()

    def update_engine_pool(self, engine_pool_id, payload):
        """Update engine pool for specific engine pool ID."""
        return self.scantron_api_query(f"/api/engine_pools/{engine_pool_id}", method="PATCH", payload=payload)

    def delete_engine_pool(self, engine_pool_id):
        """Delete an engine pool."""
        return self.scantron_api_query(f"/api/engine_pools/{engine_pool_id}", method="DELETE")

    # Engine Pools - Miscellaneous functions.
    def retrieve_engine_pools(self):
        """Retrieve information for all the engine pools."""
        return self.scantron_api_query("/api/engine_pools").json()

    def retrieve_all_scantron_information(
        self, write_to_file=False, json_dump_file_name="all_scantron_information.json"
    ):
        """Retrieve all the scantron information for easier importing/exporting."""

        all_scantron_information = {}

        try:
            engines = self.retrieve_engines()
            scan_commands = self.retrieve_scan_commands()
            scans = self.retrieve_scans()
            scheduled_scans = self.retrieve_scheduled_scans()
            sites = self.retrieve_sites()
            globally_excluded_targets = self.retrieve_globally_excluded_targets()
            engine_pools = self.retrieve_engine_pools()

            all_scantron_information["engines"] = engines
            all_scantron_information["scan_commands"] = scan_commands
            all_scantron_information["scans"] = scans
            all_scantron_information["scheduled_scans"] = scheduled_scans
            all_scantron_information["sites"] = sites
            all_scantron_information["globally_excluded_targets"] = globally_excluded_targets
            all_scantron_information["engine_pools"] = engine_pools

        except Exception as e:
            print(f"Exception: {e}")

        if write_to_file:
            print(f"Writing results to: {json_dump_file_name}")
            with open(json_dump_file_name, "w") as fh:
                json.dump(all_scantron_information, fh, indent=4)

        return all_scantron_information

    def generate_masscan_dict_from_masscan_result(self, scan_results_json, excluded_ips=[]):
        """Distills masscan json object into relevent fields.  An optional excluded_ips list of IP strings can be passed
        to ignore and not return results for specific IPs"""

        masscan_dict = {}

        for result in scan_results_json:

            # Ignore specific IPs.
            if result["ip"] in excluded_ips:
                print(f"Skipping IP: {result['ip']}")
                continue

            # Create an empty dictionary per target.
            # Duplicates ignored because data structure is a set.
            if result["ip"] not in masscan_dict:
                masscan_dict[result["ip"]] = {
                    "tcp": set(),
                    "udp": set(),
                    "icmp": set(),
                }

            for port in result["ports"]:
                if "port" in port:
                    if port["proto"] == "tcp":
                        masscan_dict[result["ip"]]["tcp"].add(port["port"])
                    elif port["proto"] == "udp":
                        masscan_dict[result["ip"]]["udp"].add(port["port"])
                    elif port["proto"] == "icmp":
                        masscan_dict[result["ip"]]["icmp"].add(port["port"])

        # Convert sets to lists.
        for key, value in masscan_dict.items():
            masscan_dict[key]["tcp"] = list(sorted(value["tcp"]))
            masscan_dict[key]["udp"] = list(sorted(value["udp"]))
            masscan_dict[key]["icmp"] = list(sorted(value["icmp"]))

        return masscan_dict

    def generate_masscan_dict_from_masscan_result_json_file(self, massscan_results_file):
        """Return a distilled masscan json object into relevent fields given a masscan results .json file."""

        masscan_dict = None

        try:
            with open(massscan_results_file, "r") as json_file:
                scan_results_json = json.load(json_file)

            masscan_dict = self.generate_masscan_dict_from_masscan_result(scan_results_json)

        except FileNotFoundError:
            print(f"File not found: {massscan_results_file}")

        return masscan_dict

    def retrieve_all_masscan_targets_with_an_open_port(self, masscan_dict):
        """Extracts all the targets with at least 1 open port and a lists of all UDP and TCP open ports found."""

        all_targets_with_an_open_port = sorted(list(set(masscan_dict.keys())))

        # Use sets to keep ports unique.
        all_open_tcp_ports = set()
        all_open_udp_ports = set()

        for ip in masscan_dict.values():
            for port in ip["tcp"]:
                all_open_tcp_ports.add(port)
            for port in ip["udp"]:
                all_open_udp_ports.add(port)

        all_open_tcp_ports_list = sorted(all_open_tcp_ports)
        all_open_udp_ports_list = sorted(all_open_udp_ports)
        all_open_tcp_ports_csv = ",".join(list(map(str, all_open_tcp_ports_list)))
        all_open_udp_ports_csv = ",".join(list(map(str, all_open_udp_ports_list)))

        all_targets_with_an_open_port_dict = {
            "all_targets_with_an_open_port_as_list": all_targets_with_an_open_port,
            "all_targets_with_an_open_port_as_csv": ",".join(all_targets_with_an_open_port),
            "all_targets_with_an_open_port_as_spaced": " ".join(all_targets_with_an_open_port),
            "all_targets_with_an_open_port_size": len(all_targets_with_an_open_port),
            "all_open_tcp_ports_list": all_open_tcp_ports_list,
            "all_open_udp_ports_list": all_open_udp_ports_list,
            "all_open_tcp_ports_csv": all_open_tcp_ports_csv,
            "all_open_udp_ports_csv": all_open_udp_ports_csv,
            "unique_open_tcp_ports": len(all_open_tcp_ports),
            "unique_open_udp_ports": len(all_open_udp_ports),
        }

        scanner_port_string = ""

        if all_open_tcp_ports:
            scanner_port_string = f"T:{all_open_tcp_ports_csv}"

        if all_open_udp_ports:
            if all_open_tcp_ports:
                scanner_port_string += ","
            scanner_port_string += f"U:{all_open_udp_ports_csv}"

        all_targets_with_an_open_port_dict["scanner_port_string"] = scanner_port_string

        return all_targets_with_an_open_port_dict

    def retrieve_all_masscan_targets_with_a_specific_port_and_protocol(self, masscan_dict, port, protocol="tcp"):
        """Retrieves all the targets with a specified open port and protocol."""

        all_targets_with_a_specific_port_and_protocol_dict = {
            "port": port,
            "protocol": protocol,
            "all_targets_with_a_specific_port_and_protocol_list": [],
            "all_targets_with_a_specific_port_and_protocol_csv": "",
            "all_targets_with_a_specific_port_and_protocol_spaced": "",
        }

        for key, value in masscan_dict.items():
            if port in masscan_dict[key][protocol]:
                all_targets_with_a_specific_port_and_protocol_dict[
                    "all_targets_with_a_specific_port_and_protocol_list"
                ].append(key)

        # Sort the targets.
        all_targets_with_a_specific_port_and_protocol_dict[
            "all_targets_with_a_specific_port_and_protocol_list"
        ] = sorted(
            all_targets_with_a_specific_port_and_protocol_dict["all_targets_with_a_specific_port_and_protocol_list"]
        )

        # Determine the total number of targets.
        all_targets_with_a_specific_port_and_protocol_dict["all_targets_with_a_specific_port_and_protocol_size"] = len(
            all_targets_with_a_specific_port_and_protocol_dict["all_targets_with_a_specific_port_and_protocol_list"]
        )

        # Create csv object from sorted list of targets.
        all_targets_with_a_specific_port_and_protocol_dict[
            "all_targets_with_a_specific_port_and_protocol_csv"
        ] = ",".join(
            all_targets_with_a_specific_port_and_protocol_dict["all_targets_with_a_specific_port_and_protocol_list"]
        )

        # Create target space delimited string from list of targets.
        all_targets_with_a_specific_port_and_protocol_dict[
            "all_targets_with_a_specific_port_and_protocol_spaced"
        ] = " ".join(
            all_targets_with_a_specific_port_and_protocol_dict["all_targets_with_a_specific_port_and_protocol_list"]
        )

        return all_targets_with_a_specific_port_and_protocol_dict

    def retrieve_all_masscan_targets_with_a_specific_port_and_protocol_from_scan_id(
        self, scan_id, port, protocol="tcp", file_type="json"
    ):
        """Retrieves all the targets with a specified open port and protocol given a scan ID.  Only supports masscan
        .json files."""

        all_targets_with_a_specific_port_and_protocol_dict = {
            "scan_id": scan_id,
            "port": port,
            "protocol": protocol,
            "all_targets_with_a_specific_port_and_protocol_list": [],
            "all_targets_with_a_specific_port_and_protocol_csv": "",
            "all_targets_with_a_specific_port_and_protocol_spaced": "",
        }

        scan_results_json = self.retrieve_scan_results(scan_id, file_type)
        masscan_dict = self.generate_masscan_dict_from_masscan_result(scan_results_json)

        all_targets_with_a_specific_port_and_protocol_dict = (
            self.retrieve_all_masscan_targets_with_a_specific_port_and_protocol(masscan_dict, port, protocol)
        )

        # Add scan ID to returned dictionary.
        all_targets_with_a_specific_port_and_protocol_dict["scan_id"] = scan_id

        return all_targets_with_a_specific_port_and_protocol_dict

    def retrieve_all_masscan_targets_and_open_ports_from_scan_id(self, scan_id, file_type="json"):
        """Retrieves all the targets and open ports given a scan ID.  Only supports masscan .json files."""

        scan_results_json = self.retrieve_scan_results(scan_id, file_type)
        masscan_dict = self.generate_masscan_dict_from_masscan_result(scan_results_json)
        all_masscan_targets_and_open_ports = self.retrieve_all_masscan_targets_with_an_open_port(masscan_dict)

        return all_masscan_targets_and_open_ports

    def wait_until_scheduled_scan_finishes(self, scheduled_scan_id, sleep_seconds=60):
        """Given a scheduled scan ID, sleep until the scan finishes."""

        while self.retrieve_scheduled_scan(scheduled_scan_id).json()["scan_status"] in ["started"]:
            print(f"Scheduled scan ID {scheduled_scan_id} is still running...sleeping {sleep_seconds} seconds.")
            time.sleep(sleep_seconds)

    def retrieve_next_available_scan_time(self):
        """Retrieves the current time on the server and returns a datetime object of the next available scan time.  If
        the current time is 11:37:04, it would return 11:38.  If the current time (11:37:46) is less than 15 seconds
        before the next minute (11:38:00), a minute will be added as a buffer and 11:39 will be returned."""

        # Retrieve the time on the server.
        # "2021-05-13T10:29:16.644174-05:00"
        server_time = self.retrieve_server_time()

        # Convert it from a string to a datetime object.
        # datetime.datetime(2021, 5, 13, 10, 29, 16, 644174, tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=68400)))
        server_time_datetime = datetime.datetime.fromisoformat(server_time)

        # Extract the current minute.
        # "29"
        minute = server_time_datetime.minute

        # Build a future time object by adding 1 minute to the current server_time_datetime object.
        server_time_future = server_time_datetime.replace(minute=(minute + 1)).replace(second=0).replace(microsecond=0)

        # If server_time_datetime is not within 15 seconds of server_time_future, use it as the next available scan
        # datetime.
        if (server_time_datetime + datetime.timedelta(seconds=15)) < server_time_future:
            next_eligible_scan_datetime = server_time_future

        # server_time_datetime is within 15 seconds of server_time_future, add another minute as a buffer.
        else:
            next_eligible_scan_datetime = server_time_future.replace(minute=(minute + 2))

        next_eligible_scan_string = f"{next_eligible_scan_datetime.hour}:{next_eligible_scan_datetime.minute}"

        return next_eligible_scan_string


if __name__ == "__main__":
    print("Use 'import scantron_api_client', do not run directly.")
    exit(1)
