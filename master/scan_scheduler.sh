#!/bin/bash

cd /home/scantron/master

source /home/scantron/master/.venv/bin/activate
python scan_scheduler.py

deactivate
