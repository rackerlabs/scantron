"""
Email validation methods for models.py and DRF's serializers.py.  Not kept in utility.py because of Django project 
loading issues.
"""
# Standard Python libraries.

# Third party Python libraries.
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

# Custom Python libraries.


def check_email_address_validity(email_address):
    """Given a string, determine if it is a valid email address using Django's validate_email() function."""

    try:
        validate_email(email_address)
        valid_email = True

    except ValidationError:
        valid_email = False

    return valid_email


def validate_string_of_email_addresses(string_of_email_addresses):
    """Given a comma deliminited string of email addresses, determine if they are all valid.  Returns a cleaned up
    version of string_of_email_addresses to be saved in the database.  Splits on commas because that is what
    console.utility.process_scan_status_change() does when sending email alerts."""

    # Remove any extra whitespaces, trailing commas, new lines, etc.
    cleaned_string_of_email_addresses = string_of_email_addresses.replace(" ", "").strip(",").strip()

    # Split on commas, remove duplicates with set(), then convert back to a list.
    email_addresses = list(set(cleaned_string_of_email_addresses.split(",")))

    for email_address in email_addresses:
        if check_email_address_validity(email_address) is False:
            raise ValidationError(
                f"Invalid email address found in string, enter comma delimited email addresses: {string_of_email_addresses}"
            )

    # List of email addresses looks good, return a comma separated string of email addresses.
    valid_emails_string = ",".join(email_addresses)

    return valid_emails_string
