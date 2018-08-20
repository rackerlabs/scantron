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
    url = "{}:{}/api/scheduled_scans/?format=json".format(
        config_data["master_address"], config_data["master_port"]
    )
    logger.ROOT_LOGGER.info("check_for_scans URL: {}".format(url))

    # Update User-Agent and add API token.
    headers = {
        "user-agent": config_data["scan_agent"],
        "Authorization": "Token {}".format(config_data["api_token"]),
    }

    try:
        # Make the HTTP GET request.
        response = requests.get(url, headers=headers, verify=False, timeout=15)

        # Return response as JSON if request is successful.
        if response.status_code == 200:
            return response.json()

        else:
            logger.ROOT_LOGGER.error(
                "Could not access {}. HTTP status code: {}".format(
                    url, response.status_code
                )
            )
            return None

    except Exception as e:
        logger.ROOT_LOGGER.error(
            "api.check_for_scans function exception: {}".format(e)
        )


def update_scan_information(config_data, scan_job, update_info):
    """Update scan information using a PATCH API request."""

    # Build URL to update scan job.
    url = "{}:{}/api/scheduled_scans/{}/".format(
        config_data["master_address"], config_data["master_port"], scan_job["id"]
    )
    logger.ROOT_LOGGER.info("update_scan_information URL: {}".format(url))

    # Update the User-Agent, add API token, and add Content-Type.
    headers = {
        "user-agent": config_data["scan_agent"],
        "Authorization": "Token {}".format(config_data["api_token"]),
        "Content-Type": "application/json",
    }

    # Make the HTTP PATCH request.
    response = requests.patch(
        url, headers=headers, verify=False, timeout=15, json=update_info
    )

    if response.status_code == 200:
        logger.ROOT_LOGGER.info(
            "Successfully updated scan information for scan ID {} with data {}".format(
                scan_job["id"], update_info
            )
        )
        return None

    else:
        logger.ROOT_LOGGER.error(
            "Could not access {} or failed to update scan ID {}. HTTP status code: {}".format(
                url, scan_job["id"], response.status_code
            )
        )
        logger.ROOT_LOGGER.error("Response content: {}".format(response.content))
        return None
