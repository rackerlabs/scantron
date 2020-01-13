#!/usr/bin/env python
# Standard Python libraries.
import argparse
import datetime
import http.client
import json
import logging
import multiprocessing
import os
import queue
import shutil
import subprocess
import ssl
import sys
import threading
import time

# Third party Python libraries.
# The goal of agent.py is to utilize native Python libraries and not depend on third party or custom packages.

# Custom Python libraries.
# The goal of agent.py is to utilize native Python libraries and not depend on third party or custom packages.

# Logging support and functions.
################################
ROOT_LOGGER = logging.getLogger("scantron")

# ISO8601 datetime format by default.
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s")


def log_timestamp():
    """Return a timestamp formatted for logs."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)
    return timestamp


# Utility functions.
####################
def get_current_time():
    """Retrieve a Django compliant pre-formated datetimestamp."""

    now_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return now_datetime


# API functions
###############
def check_for_scan_jobs(config_data):
    """Check for new scans through the API."""

    # Build URL to pull new scan jobs.  Server determines jobs based off agent (user) making request.
    master_address = config_data["master_address"]
    master_port = config_data["master_port"]
    scan_agent = config_data["scan_agent"]
    api_token = config_data["api_token"]

    ROOT_LOGGER.info(f"check_for_scans URL: {master_address}:{master_port}")

    # Update User-Agent and add API token.
    # fmt:off
    headers = {
        "user-agent": scan_agent,
        "Authorization": f"Token {api_token}",
    }
    # fmt:off

    try:
        # Make the HTTP GET request.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(master_address, port=master_port, timeout=15, context=context)
        connection.request("GET", "/api/scheduled_scans", headers=headers)

        response = connection.getresponse()
        response_code = response.code
        response_data = response.read().decode("utf-8")

        # Return response as JSON if request is successful.
        if response_code == 200:
            json_data = json.loads(response_data)
            return json_data

        else:
            ROOT_LOGGER.error(f"Could not access {master_address}:{master_port}. HTTP status code: {response_code}")
            return None

    except Exception as e:
        ROOT_LOGGER.error(f"api.check_for_scan_jobs function exception: {e}")
        ROOT_LOGGER.error(f"Response content: {response.read()}")


def update_scan_information(config_data, scan_job, update_info):
    """Update scan information using a PATCH API request."""

    master_address = config_data["master_address"]
    master_port = config_data["master_port"]
    scan_agent = config_data["scan_agent"]
    api_token = config_data["api_token"]
    scan_job_id = scan_job["id"]

    # Build URL to update scan job.
    ROOT_LOGGER.info(f"update_scan_information URL: {master_address}:{master_port}/api/scheduled_scans/{scan_job_id}")

    # Update the User-Agent, API token, and Content-Type.
    # fmt:off
    headers = {
        "user-agent": scan_agent,
        "Authorization": f"Token {api_token}",
        "Content-Type": "application/json",
    }
    # fmt:on

    # Make the HTTP PATCH request.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(master_address, port=master_port, timeout=15, context=context)
    connection.request("PATCH", f"/api/scheduled_scans/{scan_job_id}", body=json.dumps(update_info), headers=headers)

    response = connection.getresponse()
    response_code = response.code
    response_data = response.read().decode("utf-8")

    if response_code == 200:
        ROOT_LOGGER.info(
            f"Successfully updated scan information for scan ID {scan_job_id} with data {update_info}"
        )
        return None

    else:
        ROOT_LOGGER.error(
            f"Could not access {master_address}:{master_port} or failed to update scan ID {scan_job_id}. HTTP status code: {response_code}"
        )
        ROOT_LOGGER.error(f"Response content: {response_data}")
        return None


# Scanner functions.
####################
def build_masscan_command(scan_command, target_file, excluded_target_file, json_file, http_useragent):
    """Builds the masscan command."""

    # Can only have 1 file output type.
    file_options = f"-iL {target_file} -oJ {json_file} --http-user-agent {http_useragent}"

    if excluded_target_file:
        file_options += f" --excludefile {excluded_target_file}"

    # scan_command is used for both nmap and masscan commands.
    masscan_command = f"masscan {scan_command} {file_options}"

    return masscan_command


def scan_site(scan_job_dict):
    """Start nmap scans."""

    try:
        # Unpack the scan_job_dict dictionary.
        scan_job = scan_job_dict["scan_job"]
        config_data = scan_job_dict["config_data"]

        # Assign variables.
        scan_job_id = scan_job["id"]
        site_name = scan_job["site_name"]
        scan_binary = scan_job["scan_binary"]
        scan_command = scan_job["scan_command"]
        result_file_base_name = scan_job["result_file_base_name"]

        http_useragent = config_data["http_useragent"]
        scan_results_dir = config_data["scan_results_dir"]
        target_files_dir = config_data["target_files_dir"]
        target_file = os.path.join(target_files_dir, f"{result_file_base_name}.targets")

        # Write targets to a file.
        # "Passing a huge list of hosts is often awkward on the command line...Each entry must be separated by one or
        # more spaces, tabs, or newlines."
        # https://nmap.org/book/man-target-specification.html
        targets = scan_job["targets"]  # Extract string of targets.

        with open(target_file, "w") as fh:
            fh.write(f"{targets}")

        # Write excluded targets to file if specified.
        excluded_targets = scan_job["excluded_targets"]  # Extract string of targets.
        excluded_target_file = None

        if excluded_targets:
            excluded_target_file = os.path.join(target_files_dir, f"{result_file_base_name}.excluded_targets")
            with open(excluded_target_file, "w") as fh:
                fh.write(f"{excluded_targets}")

        # Setup folder structure.
        pending_files_dir = os.path.join(scan_results_dir, "pending")
        complete_files_dir = os.path.join(scan_results_dir, "complete")

        if scan_binary == "masscan":
            # Output format.
            # xml_file = os.path.join(pending_files_dir, "{}.xml".format(result_file_base_name))
            json_file = os.path.join(pending_files_dir, f"{result_file_base_name}.json")

            # Check if the paused.conf file already exists and resume scan.
            # Only 1 paused.conf file exists, and can be overwritten with a different scan.
            if os.path.isfile("paused.conf"):
                with open("paused.conf", "r") as fh:
                    paused_file = fh.read()

                    # Move back to the beginning of the file.
                    fh.seek(0, 0)

                    paused_file_lines = fh.readlines()

                ROOT_LOGGER.info(f"Previous paused.conf scan file found: {paused_file}")

                # Need to check if output-filename is the same as json_file.
                paused_file_output_filename = None
                for line in paused_file_lines:
                    if line.startswith("output-filename"):
                        paused_file_output_filename = line.split(" = ")[1].strip()

                ROOT_LOGGER.info("Checking if the output-filename is the same.")

                if paused_file_output_filename == json_file:
                    ROOT_LOGGER.info(
                        f"paused.conf file's output-filename '{paused_file_output_filename}' matches this scan request "
                        f"output filename '{json_file}'"
                    )
                    command = "masscan --resume paused.conf"

                else:
                    ROOT_LOGGER.info(
                        f"paused.conf file's output-filename '{paused_file_output_filename}' does not match this scan"
                        f"request output filename '{json_file}'.  Starting a new masscan scan."
                    )

                    # Build the masscan command.
                    command = build_masscan_command(
                        scan_command, target_file, excluded_target_file, json_file, http_useragent
                    )

            # New scan.
            else:
                # Build the masscan command.
                command = build_masscan_command(
                    scan_command, target_file, excluded_target_file, json_file, http_useragent
                )

        elif scan_binary == "nmap":
            # Three different nmap scan result file types.
            gnmap_file = os.path.join(pending_files_dir, f"{result_file_base_name}.gnmap")
            nmap_file = os.path.join(pending_files_dir, f"{result_file_base_name}.nmap")
            xml_file = os.path.join(pending_files_dir, f"{result_file_base_name}.xml")

            # Check if the file already exists and resume scan.
            if os.path.isfile(gnmap_file):
                ROOT_LOGGER.info(f"Previous scan file found '{gnmap_file}'.  Resuming the scan.")
                command = f"nmap --resume {gnmap_file}"

            # New scan.
            else:
                # Build the nmap command.
                file_options = (
                    f"-iL {target_file} -oG {gnmap_file} -oN {nmap_file} -oX {xml_file}"
                    f" --script-args http.useragent='{http_useragent}'"
                )
                if excluded_target_file:
                    file_options += f" --excludefile {excluded_target_file}"

                command = f"nmap {scan_command} {file_options}"

        else:
            ROOT_LOGGER.error(f"Invalid scan binary specified: {scan_binary}")

        # Start the scan.
        ROOT_LOGGER.info(f"Starting scan for site '{site_name}' with command: {command}")

        # Start nmap scan.
        process = subprocess.Popen(command.split())
        process.wait()

        # nmap process completed successfully.
        # Move files from "pending" directory to "complete" directory.
        if process.returncode == 0:

            if scan_binary == "masscan":
                shutil.move(json_file, os.path.join(complete_files_dir, os.path.basename(json_file)))

            elif scan_binary == "nmap":
                shutil.move(nmap_file, os.path.join(complete_files_dir, os.path.basename(nmap_file)))
                shutil.move(gnmap_file, os.path.join(complete_files_dir, os.path.basename(gnmap_file)))
                shutil.move(xml_file, os.path.join(complete_files_dir, os.path.basename(xml_file)))

            # Update completed_time, scan_status, and result_file_base_name.
            now_datetime = get_current_time()
            update_info = {
                "completed_time": now_datetime,
                "scan_status": "completed",
                "result_file_base_name": result_file_base_name,
            }

            update_scan_information(config_data, scan_job, update_info)

    except Exception as e:
        ROOT_LOGGER.exception(f"Error with scan ID {scan_job_id}.  Exception: {e}")
        update_info = {"scan_status": "error"}
        update_scan_information(config_data, scan_job, update_info)


class Worker(threading.Thread):
    """Worker thread"""

    def __init__(self):
        """Initialize Worker thread."""

        threading.Thread.__init__(self)

    def run(self):
        """Start Worker thread."""

        while True:
            # Grab scan_job_dict off the queue.
            scan_job_dict = agent.queue.get()

            try:
                # Kick off scan.
                scan_process = multiprocessing.Process(target=scan_site, args=(scan_job_dict,))
                scan_process.start()

            except Exception as e:
                ROOT_LOGGER.error(f"Failed to start scan.  Exception: {e}")

            agent.queue.task_done()


class Agent:
    """Main Agent class"""

    def __init__(self, config_file):
        """Initialize Agent class"""

        self.config_file = config_file

        # Load configuration file.
        self.config_data = self.load_config(self.config_file)

        # Create queue.
        self.queue = queue.Queue()

    def load_config(self, config_file):
        """Load the agent_config.json file and return a JSON object."""

        if os.path.isfile(config_file):
            with open(config_file) as fh:
                json_data = json.loads(fh.read())
                return json_data

        else:
            ROOT_LOGGER.error(f"'{config_file}' does not exist or contains no data.")
            sys.exit(0)

    def go(self):
        """Start the scan agent."""

        # Assign log level.  See README.md for more information.
        ROOT_LOGGER.setLevel((6 - self.config_data["log_verbosity"]) * 10)

        # Kickoff the threadpool.
        for i in range(self.config_data["number_of_threads"]):
            thread = Worker()
            thread.daemon = True
            thread.start()

        ROOT_LOGGER.info(f"Starting scan agent: {self.config_data['scan_agent']}", exc_info=False)

        while True:
            try:
                # Retrieve any new scan jobs from master through API.
                scan_jobs = check_for_scan_jobs(self.config_data)

                if scan_jobs:
                    for scan_job in scan_jobs:
                        ROOT_LOGGER.info(f"Executing scan job ID: {scan_job['id']}")

                        # Create new dictionary that will contain scan_job and config_data information.
                        scan_job_dict = {}
                        scan_job_dict["scan_job"] = scan_job
                        scan_job_dict["config_data"] = self.config_data

                        # Place scan_job_dict on queue.
                        self.queue.put(scan_job_dict)

                        # Allow the jobs to execute before changing status.
                        time.sleep(5)

                        # Update scan_status from "pending" to "started".
                        update_info = {"scan_status": "started"}
                        update_scan_information(self.config_data, scan_job, update_info)

                    self.queue.join()

                else:
                    ROOT_LOGGER.info(
                        f"No scan jobs found...checking back in {self.config_data['callback_interval_in_seconds']} seconds."
                    )
                    time.sleep(self.config_data["callback_interval_in_seconds"])

            except KeyboardInterrupt:
                break

        ROOT_LOGGER.critical("Stopping Scantron")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scantron scan agent")
    parser.add_argument(
        "-c",
        dest="config_file",
        action="store",
        required=False,
        default="agent_config.json",
        help="Configuration file.  Defaults to 'agent_config.json'",
    )
    args = parser.parse_args()

    config_file = args.config_file

    # Log level is controlled in agent_config.json and assigned after reading that file.
    # Setup file logging.
    log_file_handler = logging.FileHandler(os.path.join("logs", "agent.log"))
    log_file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(log_file_handler)

    # Setup console logging.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    agent = Agent(config_file)
    agent.go()
