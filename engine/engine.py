#!/usr/bin/env python
"""The goals of engine.py are to:

1) Utilize native Python libraries and not depend on third party or custom libraries
2) Be a single file so it can be easily moved, downloaded, or transferred between systems
"""

# Standard Python libraries.
import argparse
import json
import logging
import os
import queue
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

__version__ = "1.03"

# Disable SSL/TLS verification.
ssl._create_default_https_context = ssl._create_unverified_context

# Logging object.
ROOT_LOGGER = logging.getLogger("scantron")
LOG_FORMATTER = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(filename)s-%(funcName)s()] [%(levelname)s] %(message)s"
)

# Track scan process IDs, subprocess.Popen() objects, and scan status state.
SCAN_PROCESS_DICT = {}


def build_masscan_command(scan_command, target_file, excluded_target_file, json_file, http_useragent):
    """Builds the masscan command."""

    # Can only have 1 file output type.
    file_options = f"-iL {target_file} -oJ {json_file} --http-user-agent {http_useragent}"

    if excluded_target_file:
        file_options += f" --excludefile {excluded_target_file}"

    # scan_command is used for both nmap and masscan commands.
    masscan_command = f"masscan {scan_command} {file_options}"

    return masscan_command


def check_for_scan_jobs():
    """Check for new scans through the API."""

    # Build URL to pull new scan jobs.  Server determines jobs based off engine (user) making request.
    console_address = engine.config_data["console_address"]
    console_port = engine.config_data["console_port"]
    scan_engine = engine.config_data["scan_engine"]
    api_token = engine.config_data["api_token"]

    url = f"{console_address}:{console_port}/api/scheduled_scans"
    ROOT_LOGGER.info(f"check_for_scans URL: {url}")

    # Update User-Agent and add API token.
    headers = {
        "user-agent": scan_engine,
        "Authorization": f"Token {api_token}",
    }

    try:
        # Make the HTTP GET request.
        request = urllib.request.Request(method="GET", url=url, headers=headers)
        response = urllib.request.urlopen(request)

        response_code = response.status
        response_data = response.read().decode("utf-8")

        # Return response as JSON if request is successful.
        if response_code == 200:
            json_data = json.loads(response_data)
            return json_data

        else:
            ROOT_LOGGER.error(f"Could not access {console_address}:{console_port}. HTTP status code: {response_code}")
            ROOT_LOGGER.error(f"Response content: {response_data}")
            return None

    except Exception as e:
        ROOT_LOGGER.error(f"check_for_scan_jobs() function exception: {e}")


def update_scan_information(scan_job, update_info):
    """Update scan information using a PATCH API request."""

    console_address = engine.config_data["console_address"]
    console_port = engine.config_data["console_port"]
    scan_engine = engine.config_data["scan_engine"]
    api_token = engine.config_data["api_token"]
    scan_job_id = scan_job["id"]

    # Build URL to update scan job.
    url = f"{console_address}:{console_port}/api/scheduled_scans/{scan_job_id}"
    ROOT_LOGGER.info(f"update_scan_information URL: {url}")

    # Update the User-Agent, API token, and Content-Type.
    headers = {
        "user-agent": scan_engine,
        "Authorization": f"Token {api_token}",
        "Content-Type": "application/json",
    }

    # Convert dictionary to a string, then encode to bytes.
    data = json.dumps(update_info).encode("utf-8")

    # Make the HTTP PATCH request.
    request = urllib.request.Request(method="PATCH", url=url, data=data, headers=headers)
    response = urllib.request.urlopen(request)

    response_code = response.status
    response_data = response.read().decode("utf-8")

    if response_code == 200:
        ROOT_LOGGER.info(f"Successfully updated scan information for scan ID {scan_job_id} with data {update_info}")
        update_scan_information_success = True

    else:
        ROOT_LOGGER.error(
            f"Could not access {console_address}:{console_port} or failed to update scan ID {scan_job_id}. "
            f"HTTP status code: {response_code}"
        )
        ROOT_LOGGER.error(f"Response content: {response_data}")
        update_scan_information_success = False

    return update_scan_information_success


def scan_job_handler(scan_job_dict):
    """Manages different scan functionality."""

    try:
        # Unpack the scan_job_dict dictionary.
        scan_job = scan_job_dict["scan_job"]
        config_data = scan_job_dict["config_data"]

        # Assign variables from scan_job.
        scan_job_id = scan_job["id"]
        scan_status = scan_job["scan_status"]
        site_name = scan_job["site_name"]
        scan_binary = scan_job["scan_binary"]
        scan_command = scan_job["scan_command"]
        result_file_base_name = scan_job["result_file_base_name"]

        # Assign variables from config_data.
        supported_scan_binaries = config_data["supported_scan_binaries"]
        http_useragent = config_data["http_useragent"]
        scan_results_dir = config_data["scan_results_dir"]
        target_files_dir = config_data["target_files_dir"]
        target_file = os.path.join(target_files_dir, f"{result_file_base_name}.targets")

        # Setup folder directories.
        pending_files_dir = os.path.join(scan_results_dir, "pending")

        if scan_binary not in supported_scan_binaries:
            ROOT_LOGGER.error(f"Invalid scan binary specified: {scan_binary}")
            return

        # A request to pause or cancel a scan has been detected.
        if scan_status in ["pause", "cancel"]:

            ROOT_LOGGER.info(f"Received request to {scan_status} scan_job: {scan_job}")

            # Extract the process ID of the scan binary to kill.
            scan_binary_process_id = scan_job["scan_binary_process_id"]

            try:
                # Extract the subprocess.Popen() object based off the scan_binary_process_id key.
                process = SCAN_PROCESS_DICT[scan_binary_process_id]["popen_object"]

                # Ensure the scan binary name is one of the supported scan binaries.
                scan_binary = process.args[0]

                if scan_binary in supported_scan_binaries:

                    if scan_binary == "masscan" and scan_status == "pause":

                        # Update SCAN_PROCESS_DICT[scan_binary_process_id]["scan_status"] to be "paused", so in the
                        # thread doing the actual scanning, when the process.wait() realizes it's received a ctrl-c, it
                        # will check SCAN_PROCESS_DICT[scan_binary_process_id]["scan_status"] and ensure it's only in
                        # the state "started".  Even though the process receives a ctrl-c, the process.returncode == 0
                        # is not enough for it to realize the difference between a successfully completed scan and a
                        # ctrl-c signal interupt, which resulted in race condition in which the status was updated to
                        # "completed" in one thread, then updated to "paused" in the other.
                        SCAN_PROCESS_DICT[scan_binary_process_id]["scan_status"] = "paused"

                        # Simulates ctrl-c key combination to generate the paused.conf file.
                        process.send_signal(signal.SIGINT)

                        # "By default, masscan waits 10 seconds for any responses to come back after a scan is complete."
                        # https://blog.erratasec.com/2018/06/smb-version-detection-in-masscan.html
                        # TODO add logic to pull out --wait value?
                        ROOT_LOGGER.info(
                            "ctrl-c sent to the masscan process, sleeping 15 seconds to create the paused.conf file."
                        )
                        time.sleep(15)
                        ROOT_LOGGER.info("Done sleeping 15 seconds.")

                    else:
                        SCAN_PROCESS_DICT[scan_binary_process_id]["scan_status"] = "cancelled"

                        process.kill()

                    stdout, stderr = process.communicate()

                    if not stdout and not stderr:
                        ROOT_LOGGER.info(
                            f"Killed process ID {scan_binary_process_id}.  Command: {' '.join(process.args)}"
                        )

                    else:
                        ROOT_LOGGER.error(
                            f"Issue killing process ID {scan_binary_process_id}.  "
                            f"stderr: {stderr.decode()}.  stdout: {stdout.decode()}"
                        )

                    # Remove the killed process ID from the scan process dictionary.
                    SCAN_PROCESS_DICT.pop(scan_binary_process_id)

                    if scan_status == "cancel":
                        updated_scan_status = "cancelled"

                    elif scan_status == "pause":
                        updated_scan_status = "paused"

                    # Update console with the updated scan status.
                    update_info = {
                        "scan_status": updated_scan_status,
                    }
                    update_scan_information(scan_job, update_info)

            except KeyError:
                ROOT_LOGGER.error(f"Process ID {scan_binary_process_id} is not running.")

            return

        elif scan_status == "pending":
            # Write targets to a file.
            # "Passing a huge list of hosts is often awkward on the command line...Each entry must be separated by one
            # or more spaces, tabs, or newlines."
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

            if scan_binary == "masscan":
                # Output format.
                # xml_file = os.path.join(pending_files_dir, f"{result_file_base_name}.xml")
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
                            f"paused.conf file's output-filename '{paused_file_output_filename}' matches this scan "
                            f"request output filename '{json_file}'"
                        )
                        command = "masscan --resume paused.conf"

                    else:
                        ROOT_LOGGER.info(
                            f"paused.conf file's output-filename '{paused_file_output_filename}' does not match this "
                            f" scan request output filename '{json_file}'.  Starting a new masscan scan."
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

                # Check if the gnmap file already exists and resume scan.
                gnmap_file = os.path.join(pending_files_dir, f"{result_file_base_name}.gnmap")

                # Ensure the .gnmap file exists and it is greater than 0 bytes before using it.
                if os.path.isfile(gnmap_file) and (os.path.getsize(gnmap_file) > 0):
                    ROOT_LOGGER.info(f"Previous scan file found '{gnmap_file}'.  Resuming the scan.")
                    command = f"nmap --resume {gnmap_file}"

                # New scan.
                else:
                    # Build the nmap command.
                    nmap_results = os.path.join(pending_files_dir, result_file_base_name)

                    file_options = (
                        f"-iL {target_file} -oA {nmap_results} --script-args http.useragent='{http_useragent}'"
                    )
                    if excluded_target_file:
                        file_options += f" --excludefile {excluded_target_file}"

                    command = f"nmap {scan_command} {file_options}"

            # Placeholder if other scan binaries are added.
            else:
                return

            # Spawn a new process for the scan.
            process = subprocess.Popen(command.split())

            # Extract PID.
            scan_binary_process_id = process.pid

            # Track the process ID and subprocess.Popen() object.
            SCAN_PROCESS_DICT[scan_binary_process_id] = {
                "popen_object": process,
                "scan_status": "started",
            }

            # Start the scan.
            ROOT_LOGGER.info(
                f"Starting scan for site '{site_name}', with process ID {scan_binary_process_id}, and command: {command}"
            )

            # Update console with the process ID.
            update_info = {
                "scan_status": "started",
                "scan_binary_process_id": scan_binary_process_id,
            }
            update_scan_information(scan_job, update_info)

            process.wait()

            ROOT_LOGGER.debug(f"process.returncode: {process.returncode}")

            # process.returncode = 0 for completed (nmap/masscan) and SIGINT processes (masscan)
            # process.returncode = -9 for killed processes (nmap/masscan)
            if process.returncode == 0:

                # Scan binary process completed successfully.  scan_status == "paused" for masscan processes only. This
                # check ensures the scan status of a masscan process isn't "paused".
                if SCAN_PROCESS_DICT[scan_binary_process_id]["scan_status"] == "started":

                    # Update scan_status.
                    update_info = {
                        "scan_status": "completed",
                    }

                    update_scan_information(scan_job, update_info)

                    # Remove the completed process ID from the scan process dictionary.
                    SCAN_PROCESS_DICT.pop(scan_binary_process_id)

        else:
            ROOT_LOGGER.error(f"Unsupported scan_status: {scan_status}")

    except Exception as e:
        ROOT_LOGGER.exception(f"Error with scan ID {scan_job_id}.  Exception: {e}")
        update_info = {"scan_status": "error"}
        update_scan_information(scan_job, update_info)

    return


class Worker(threading.Thread):
    """Worker thread"""

    def __init__(self):
        """Initialize Worker thread."""

        threading.Thread.__init__(self)

    def run(self):
        """Start Worker thread."""

        while True:

            # Grab scan_job_dict off the queue.
            scan_job_dict = engine.queue.get()

            try:
                # Kick off scan.
                scan_job_handler(scan_job_dict)

            except Exception as e:
                ROOT_LOGGER.error(f"Failed to call scan_job_handler.  Exception: {e}")

            engine.queue.task_done()


class Engine:
    """Main Engine class"""

    def __init__(self, config_file):
        """Initialize Engine class"""

        # Load configuration file.
        self.config_data = self.load_config(config_file)

        # Create queue.
        self.queue = queue.Queue()

    def load_config(self, config_file):
        """Load the engine_config.json file and return a JSON object."""

        if os.path.isfile(config_file):
            with open(config_file) as fh:
                json_data = json.loads(fh.read())
                return json_data

        else:
            ROOT_LOGGER.error(f"'{config_file}' does not exist or contains no data.")
            sys.exit(0)

    def go(self):
        """Start the scan engine."""

        # Assign log level.  See README.md for more information.
        ROOT_LOGGER.setLevel((6 - self.config_data["log_verbosity"]) * 10)

        # Kickoff the threadpool.
        for i in range(self.config_data["number_of_threads"]):
            thread = Worker()
            thread.daemon = True
            thread.start()

        ROOT_LOGGER.info(f"Starting scan engine: {self.config_data['scan_engine']}", exc_info=False)

        while True:

            try:

                ROOT_LOGGER.info(f"Current scan processes being tracked in SCAN_PROCESS_DICT: {SCAN_PROCESS_DICT}")

                # Retrieve any new scan jobs from console through API.
                scan_jobs = check_for_scan_jobs()

                if scan_jobs:
                    for scan_job in scan_jobs:

                        ROOT_LOGGER.info(f"scan_job: {json.dumps(scan_job, indent=4)}")

                        # Create new dictionary that will contain scan_job and config_data information.
                        scan_job_dict = {
                            "scan_job": scan_job,
                            "config_data": self.config_data,
                        }

                        # Place scan_job_dict on queue.
                        self.queue.put(scan_job_dict)

                        # Provide some breathing room for the jobs to execute.
                        time.sleep(5)

                    # Don't wait for threads to finish.
                    # self.queue.join()

                else:
                    ROOT_LOGGER.info(
                        f"No scan jobs found...checking back in {self.config_data['callback_interval_in_seconds']} seconds."
                    )

                time.sleep(self.config_data["callback_interval_in_seconds"])

            except KeyboardInterrupt:
                break

        ROOT_LOGGER.critical("Stopping Scantron engine")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scantron scan engine")
    parser.add_argument(
        "-c",
        dest="config_file",
        action="store",
        required=False,
        default="engine_config.json",
        help="Configuration file.  Defaults to 'engine_config.json'",
    )
    parser.add_argument(
        "-v", dest="version", action="store_true", required=False, help="Print engine version",
    )

    args = parser.parse_args()

    if args.version:
        print(f"Scantron engine version: {__version__}")
        sys.exit(0)

    if not shutil.which("nmap"):
        print(f"Path for nmap cannot be found.  Exiting...")
        sys.exit(0)

    if not shutil.which("masscan"):
        print(f"Path for masscan cannot be found.  Exiting...")
        sys.exit(0)

    if not os.path.isdir("./logs"):
        print("./logs directory does not exist, creating it.")
        os.mkdir("./logs", mode=0o700)

    # Log level is controlled in engine_config.json and assigned after reading that file.
    # Setup file logging
    log_file_handler = logging.FileHandler(os.path.join("logs", "engine.log"))
    log_file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(log_file_handler)

    # Setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    ROOT_LOGGER.info(f"Starting scantron engine version: v{__version__}")

    engine = Engine(args.config_file)
    engine.go()
