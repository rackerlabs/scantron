#!/bin/bash

cd /home/scantron/master/nmap_results

source /home/scantron/master/.venv/bin/activate
python nmap_to_csv.py

deactivate
