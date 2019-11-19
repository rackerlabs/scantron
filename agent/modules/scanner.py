# Standard Python libraries.
import os
import shutil
import subprocess

# Third party Python libraries.


# Custom Python libraries.
from . import api
from . import utils
from . import logger


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
        scan_command = scan_job["scan_command"]  # Also used for masscan.
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

                logger.ROOT_LOGGER.info(f"Previous paused.conf scan file found: {paused_file}")

                # Need to check if output-filename is the same as json_file.
                paused_file_output_filename = None
                for line in paused_file_lines:
                    if line.startswith("output-filename"):
                        paused_file_output_filename = line.split(" = ")[1].strip()

                logger.ROOT_LOGGER.info("Checking if the output-filename is the same.")

                if paused_file_output_filename == json_file:
                    logger.ROOT_LOGGER.info(
                        f"paused.conf file's output-filename '{paused_file_output_filename}' matches this scan request "
                        f"output filename '{json_file}'"
                    )
                    command = "masscan --resume paused.conf"

                else:
                    logger.ROOT_LOGGER.info(
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
                logger.ROOT_LOGGER.info(f"Previous scan file found '{gnmap_file}'.  Resuming the scan.")
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
            logger.ROOT_LOGGER.error(f"Invalid scan binary specified: {scan_binary}")

        # Start the scan.
        logger.ROOT_LOGGER.info(f"Starting scan for site '{site_name}' with command: {command}")

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
            now_datetime = utils.get_current_time()
            update_info = {
                "completed_time": now_datetime,
                "scan_status": "completed",
                "result_file_base_name": result_file_base_name,
            }

            api.update_scan_information(config_data, scan_job, update_info)

    except Exception as e:
        logger.ROOT_LOGGER.exception(f"Error with scan ID {scan_job_id}.  Exception: {e}")
        update_info = {"scan_status": "error"}
        api.update_scan_information(config_data, scan_job, update_info)
