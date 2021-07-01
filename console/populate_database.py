#!/usr/bin/env python
# Standard Python libraries.
import json

# Third party Python libraries.

# Custom Python libraries.
import django_connector


def populate_configuration():

    print("Populating Configuration")

    with open("configuration.json", "r") as fh:
        json_data = json.load(fh)

    try:
        configuration, created = django_connector.Configuration.objects.update_or_create(id=1, defaults=json_data,)

    except Exception as e:
        print(e)


if __name__ == "__main__":

    populate_configuration()
