# Standard Python libraries.
import json
import sys
import urllib3

# Third party Python libraries.
import requests

# Custom Python libraries.
import utility

__version__ = "1.1"


class ScantronClient:
    def __init__(self, **kwargs):
        """Initialize a Scantron client."""

        secrets_file_location = "./scantron_api_secrets.json"

        SECRETS = {}

        try:
            with open(secrets_file_location) as config_file:
                SECRETS = json.loads(config_file.read())
        except OSError:
            print(f"Error: {secrets_file_location} does not exist.  Exiting...")
            sys.exit(1)

        # Ensure key/values exist in secrets.json.
        try:
            self.host = SECRETS["host"]
            self.port = SECRETS["port"]
            self.token = SECRETS["token"]

        except KeyError:
            print(f"Error reading key-values in {secrets_file_location} file.  Exiting...")
            sys.exit(1)

        # Build BASE_URL.
        self.BASE_URL = f"https://{self.host}:{self.port}"

        # Minimize Python requests (and the underlying urllib3 library) logging level.
        # logging.getLogger("requests").setLevel(print)
        # logging.getLogger("urllib3").setLevel(print)

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {self.token}",
        }

        # Extract timeout, default to 30 seconds.
        self.timeout = kwargs.get("timeout", 30)

        # Extract self_signed, default to True.
        self.api_self_signed = kwargs.get("api_self_signed", True)

        # Extract max attempts, default to 3.
        self.max_attempts = kwargs.get("max_attempts", 3)

        if self.api_self_signed:
            urllib3.disable_warnings()

    def scantron_api_query(self, endpoint, **kwargs):
        """Executes a properly formatted API call to the Scantron API with the supplied arguments."""

        url = f"{self.BASE_URL}/{endpoint}"

        # Set HTTP headers.
        headers = kwargs.get("headers", {})

        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {self.token}",
        }

        if not isinstance(headers, dict):
            raise ValueError("headers keyword passed to scantron_api_query is not a valid dict object")

        # Merge dictionaries.
        # https://treyhunner.com/2016/02/how-to-merge-dictionaries-in-python/
        headers = {**default_headers, **headers}

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
                        utility.debug_requests_response(response, endpoint, payload, parameters)

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
                        utility.debug_requests_response(response, endpoint, payload, parameters)

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
                        utility.debug_requests_response(response, endpoint, payload, parameters)

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
                        utility.debug_requests_response(response, endpoint, payload, parameters)

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
                        utility.debug_requests_response(response, endpoint, payload, parameters)

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

        return response

    # Scan Results
    ##############
    def retrieve_scan_results(self, scan_id, file_type, **kwargs):
        """Returns a text blob of the scan results if they actually exist.  For .json files, you can convert it to a
        Python JSON object using:
        scan_results_json = json.loads(scan_results)"""

        scan_results = None

        if file_type.lower() not in ["nmap", "xml", "json"]:
            print(f"Not a valid file type: {file_type}")

        else:
            response = self.scantron_api_query(f"/results/{scan_id}?file_type={file_type}", **kwargs)

            # Only return the results if they actually exist.
            if response.status_code == 200:
                scan_results = response.text

        return scan_results

    # AGENTS
    ########
    # Agents - CRUD functions.
    def create_agent(self):
        """Create a scan command."""
        print("no create function, an Agent is created when a Django User is created.")
        return None

    def retrieve_agent(self, agent_id):
        """Retrieve an agent."""
        return self.scantron_api_query(f"/api/agents/{agent_id}", method="GET")

    def update_agent(self, agent_id, payload):
        """Update an agent."""
        return self.scantron_api_query(f"/api/agents/{agent_id}", method="PATCH", payload=payload)

    def delete_agent(self, agent_id):
        """Delete an agent."""
        return self.scantron_api_query(f"/api/agents/{agent_id}", method="DELETE")

    # Agents - Miscellaneous functions.
    def retrieve_agents(self, **kwargs):
        """Retrieve information for all the agents."""
        return self.scantron_api_query("/api/agents").json()

    def retrieve_agent_id_from_agent_name(self, agent_name):
        """Retrieve the agent ID, given an agent name."""

        agents = self.retrieve_agents()

        agent_id = None

        for agent in agents:
            if agent["scan_agent"].lower() == agent_name.lower():
                agent_id = agent["id"]

        return agent_id

    # Scan Commands
    ###############
    # Scan Commands - CRUD functions.
    def create_scan_command(self, payload):
        """Create a scan command"""
        return self.scantron_api_query("/api/scan_commands", method="POST", payload=payload)

    def retrieve_scan_command(self, scan_command_id, **kwargs):
        """Retrieve scan command."""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="GET").json()

    def update_scan_command(self, scan_command_id, payload):
        """Update scan command for specific scan command ID"""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="PATCH", payload=payload)

    def delete_scan_command(self, scan_command_id):
        """Delete a scan"""
        return self.scantron_api_query(f"/api/scan_commands/{scan_command_id}", method="DELETE")

    # Scan Commands - Miscellaneous functions.
    def retrieve_scan_commands(self, **kwargs):
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
        """Create a scan"""
        return self.scantron_api_query("/api/scans", method="POST", payload=payload)

    def retrieve_scan(self, scan_id):
        """Retrieve a scan."""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="GET")

    def update_scan(self, scan_id, payload):
        """Update scan for specific scan ID"""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="PATCH", payload=payload)

    def delete_scan(self, scan_id):
        """Delete a scan"""
        return self.scantron_api_query(f"/api/scans/{scan_id}", method="DELETE")

    # Scans - Miscellaneous functions.
    def retrieve_scans(self, **kwargs):
        """Retrieve information for all the scans."""
        return self.scantron_api_query("/api/scans").json()

    # SCHEDULED SCANS
    #################
    def retrieve_scheduled_scans(self, **kwargs):
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
        """Delete a site"""
        return self.scantron_api_query(f"/api/sites/{site_id}", method="DELETE")

    # Sites - Miscellaneous functions.
    def retrieve_sites(self, **kwargs):
        """Retrieve information for all the sites."""
        return self.scantron_api_query(f"/api/sites").json()

    def retrieve_site_id_from_site_name(self, site_name):
        """Retrieve the site ID, given a site name."""

        sites_info = self.retrieve_sites()

        site_id = None

        for site in sites_info:
            if site["site_name"].lower() == site_name.lower():
                site_id = site["id"]

        return site_id

    def retrieve_all_scantron_information(
        self, write_to_file=False, json_dump_file_name="all_scantron_information.json"
    ):
        """Retrieve all the scantron information for easier importing/exporting."""

        all_scantron_information = {}

        try:
            agents = self.retrieve_agents()
            scan_commands = self.retrieve_scan_commands()
            scans = self.retrieve_scans()
            scheduled_scans = self.retrieve_scheduled_scans()
            sites = self.retrieve_sites()

            all_scantron_information["agents"] = agents
            all_scantron_information["scan_commands"] = scan_commands
            all_scantron_information["scans"] = scans
            all_scantron_information["scheduled_scans"] = scheduled_scans
            all_scantron_information["sites"] = sites

        except Exception as e:
            print(f"Exception: {e}")

        if write_to_file:
            print(f"Writing results to: {json_dump_file_name}")
            with open(json_dump_file_name, "w") as fh:
                json.dump(all_scantron_information, fh, indent=4)

        return all_scantron_information


if __name__ == "__main__":
    print("Use 'import scantron_api_client', do not run directly.")
    exit(1)
