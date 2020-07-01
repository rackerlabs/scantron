#!/bin/bash

cd /home/scantron/console

source /home/scantron/console/.venv/bin/activate
python scan_scheduler.py

deactivate
