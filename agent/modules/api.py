#!/usr/bin/env python
# Standard Python libraries.


# Third party Python libraries.
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Custom Python libraries.
from . import logger

# Disable warning: "InsecureRequestWarning: Unverified HTTPS request is being made.
# Adding certificate verification is strongly advised"
# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def check_for_scan_jobs(config_data):
    """Check for new scans through the API."""

    # Build URL to pull new scan jobs.  Server determines jobs based off agent (user) making request.
    master_address = config_data["master_address"]
    master_port = config_data["master_port"]
    api_token = config_data["api_token"]

    url = f"{master_address}:{master_port}/api/scheduled_scans"
    logger.ROOT_LOGGER.info(f"check_for_scans URL: {url}")

    # Update User-Agent and add API token.
    # fmt:off
    headers = {
        "user-agent": config_data["scan_agent"],
        "Authorization": f"Token {api_token}",
    }
    # fmt:on

    try:
        # Make the HTTP GET request.
        response = requests.get(url, headers=headers, verify=False, timeout=15)

        # Return response as JSON if request is successful.
        if response.status_code == 200:
            return response.json()

        else:
            logger.ROOT_LOGGER.error(f"Could not access {url}. HTTP status code: {response.status_code}")
            return None

    except Exception as e:
        logger.ROOT_LOGGER.error(f"api.check_for_scan_jobs function exception: {e}")


def update_scan_information(config_data, scan_job, update_info):
    """Update scan information using a PATCH API request."""

    master_address = config_data["master_address"]
    master_port = config_data["master_port"]
    api_token = config_data["api_token"]
    scan_agent = config_data["scan_agent"]
    scan_job_id = scan_job["id"]

    # Build URL to update scan job.
    url = f"{master_address}:{master_port}/api/scheduled_scans/{scan_job_id}"
    logger.ROOT_LOGGER.info(f"update_scan_information URL: {url}")

    # Update the User-Agent, API token, and Content-Type.
    # fmt:off
    headers = {
        "user-agent": scan_agent,
        "Authorization": f"Token {api_token}",
        "Content-Type": "application/json",
    }
    # fmt:on

    # Make the HTTP PATCH request.
    response = requests.patch(url, headers=headers, verify=False, timeout=15, json=update_info)

    if response.status_code == 200:
        logger.ROOT_LOGGER.info(
            f"Successfully updated scan information for scan ID {scan_job_id} with data {update_info}"
        )
        return None

    else:
        logger.ROOT_LOGGER.error(
            f"Could not access {url} or failed to update scan ID {scan_job_id}. HTTP status code: {response.status_code}"
        )
        logger.ROOT_LOGGER.error(f"Response content: {response.content}")
        return None
