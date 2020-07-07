#!/bin/bash

# Runs as a cronjob every minute.  If the NFS share is not established, re-mounts it.

scan_results="$(stat -f -L -c %T /root/engine/scan_results)"
target_files="$(stat -f -L -c %T /root/engine/target_files)"

if [ "$scan_results" != "nfs" ]
then
    echo "[+] mounting scan_results"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/console/scan_results /root/engine/scan_results
fi

if [ "$target_files" != "nfs" ]
then
    echo "[+] mounting target_files"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/console/target_files /root/engine/target_files
fi
