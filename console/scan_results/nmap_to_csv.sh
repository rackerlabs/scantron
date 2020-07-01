#!/bin/bash

cd /home/scantron/console/scan_results

source /home/scantron/console/.venv/bin/activate
python nmap_to_csv.py

deactivate
