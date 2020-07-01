# Actual file used is kept in scantron/ansible-playbooks/roles/console/templates/django_connector.py.j2
# Modifying this file will do nothing if you are using the Ansible playbook.

import os
import sys

# Django connector information.
import django

project_path = "."
sys.path.append(project_path)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")
django.setup()
# fmt: off
from django_scantron.models import (  # noqa
    Scan,
    ScheduledScan,
    Site,
)
# fmt: on
