#!/bin/bash

cd /home/scantron/console

source /home/scantron/console/.venv/bin/activate
python scan_retention.py -b -c -r -v 5

deactivate
