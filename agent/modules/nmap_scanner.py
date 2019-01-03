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
        scan_binary = scan_job["scan_binary"]
        nmap_command = scan_job["nmap_command"]  # Also used for masscan.
        result_file_base_name = scan_job["result_file_base_name"]

        nmap_results_dir = config_data["nmap_results_dir"]

        target_files_dir = config_data["target_files_dir"]
        target_file = os.path.join(target_files_dir, scan_job["target_file"])

        # Setup folder structure.
        pending_files_dir = os.path.join(nmap_results_dir, "pending")
        complete_files_dir = os.path.join(nmap_results_dir, "complete")

        if scan_binary == "masscan":
            # Output format.
            # xml_file = os.path.join(pending_files_dir, "{}.xml".format(result_file_base_name))
            json_file = os.path.join(pending_files_dir, "{}.json".format(result_file_base_name))

            # Check if the paused.conf file already exists and resume scan.
            # Only 1 paused.conf file exists, and can be overwritten with a different scan.
            if os.path.isfile("paused.conf"):
                with open("paused.conf", "r") as fh:
                    paused_file = fh.read()

                    # Move back to the beginning of the file.
                    fh.seek(0, 0)

                    paused_file_lines = fh.readlines()

                logger.ROOT_LOGGER.info("Previous paused.conf scan file found: {}".format(paused_file))

                # Need to check if output-filename is the same as json_file.
                paused_file_output_filename = None
                for line in paused_file_lines:
                    if line.startswith("output-filename"):
                        paused_file_output_filename = line.split(" = ")[1].strip()

                logger.ROOT_LOGGER.info("Checking if the output-filename is the same.")

                if paused_file_output_filename == json_file:
                    logger.ROOT_LOGGER.info(
                        "paused.conf file's output-filename '{}' matches this scan request output filename '{}'".format(
                            paused_file_output_filename, json_file
                        )
                    )
                    command = "masscan --resume paused.conf"

                else:
                    logger.ROOT_LOGGER.info(
                        "paused.conf file's output-filename '{}' does not match this scan request output filename '{}'".format(
                            paused_file_output_filename, json_file
                        )
                    )
                    return

            # New scan.
            else:
                # Build the masscan command.
                # Can only have 1 file output type.
                file_options = "-iL {} -oJ {} --http-user-agent {}".format(
                    target_file, json_file, config_data["http_useragent"]
                )

                # nmap_command is used for both nmap and masscan commands.
                command = "masscan {} {}".format(nmap_command, file_options)

        elif scan_binary == "nmap":
            # Three different nmap scan result file types.
            gnmap_file = os.path.join(pending_files_dir, "{}.gnmap".format(result_file_base_name))
            nmap_file = os.path.join(pending_files_dir, "{}.nmap".format(result_file_base_name))
            xml_file = os.path.join(pending_files_dir, "{}.xml".format(result_file_base_name))

            # Check if the file already exists and resume scan.
            if os.path.isfile(gnmap_file):
                logger.ROOT_LOGGER.info("Previous scan file found '{}'.  Resuming the scan.".format(gnmap_file))

                command = "nmap --resume {}".format(gnmap_file)

            # New scan.
            else:
                # Build the nmap command.
                file_options = "-iL {} -oG {} -oN {} -oX {} --script-args http.useragent='{}'".format(
                    target_file, gnmap_file, nmap_file, xml_file, config_data["http_useragent"]
                )
                command = "nmap {} {}".format(nmap_command, file_options)

        else:
            logger.ROOT_LOGGER.error("Invalid scan binary specified: {}".format(scan_binary))

        # Start the scan.
        logger.ROOT_LOGGER.info("Starting scan for site '{}' with command: {}".format(site_name, command))

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
        logger.ROOT_LOGGER.exception("Error with scan ID {}.  Exception: {}".format(scan_job["id"], e))
        update_info = {"scan_status": "error"}
        api.update_scan_information(config_data, scan_job, update_info)
