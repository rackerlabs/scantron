# Standard Python libraries.
import os
import shutil
import subprocess

# Third party Python libraries.


# Custom Python libraries.
from . import api
from . import utils
from . import logger


def scan_site(scan_job_dict):
    """Start nmap scans."""

    try:
        # Unpack the scan_job_dict dictionary.
        scan_job = scan_job_dict["scan_job"]
        config_data = scan_job_dict["config_data"]

        # Assign variables.
        site_name = scan_job["site_name"]
        nmap_command = scan_job["nmap_command"]
        result_file_base_name = scan_job["result_file_base_name"]

        nmap_results_dir = config_data["nmap_results_dir"]

        target_files_dir = config_data["target_files_dir"]
        targets_file = os.path.join(target_files_dir, scan_job["targets_file"])

        # Setup folder structure.
        pending_files_dir = os.path.join(nmap_results_dir, "pending")
        complete_files_dir = os.path.join(nmap_results_dir, "complete")

        # Three different scan result file types.
        gnmap_file = os.path.join(pending_files_dir, "{}.gnmap".format(result_file_base_name))
        nmap_file = os.path.join(pending_files_dir, "{}.nmap".format(result_file_base_name))
        xml_file = os.path.join(pending_files_dir, "{}.xml".format(result_file_base_name))

        # Check if the file already exists and resume scan.
        if os.path.isfile(nmap_file):
            logger.ROOT_LOGGER.info("Previous scan file found '{}'.  Resuming the scan.".format(nmap_file))

            command = "nmap --resume {}".format(nmap_file)

        # New scan.
        else:
            # Build the nmap command.
            file_options = "-iL {} -oG {} -oN {} -oX {} --script-args http.useragent='{}'".format(
                targets_file, gnmap_file, nmap_file, xml_file, config_data["http_useragent"]
            )
            command = "nmap {} {}".format(nmap_command, file_options)

        # Start the scan.
        logger.ROOT_LOGGER.info("Starting scan for site '{}' with command: {}".format(site_name, command))

        # Start nmap scan.
        process = subprocess.Popen(command.split())
        process.wait()

        # nmap process completed successfully.
        if process.returncode == 0:
            # Move files from "pending" directory to "complete" directory.
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
        logger.ROOT_LOGGER.error("Error with scan ID {}.  Exception: {}".format(scan_job["id"], e))
        update_info = {"scan_status": "error"}
        api.update_scan_information(config_data, scan_job, update_info)
