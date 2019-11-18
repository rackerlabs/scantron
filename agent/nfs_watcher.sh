#!/bin/bash

# Runs as a cronjob every minute.  If the NFS share is not established, re-mounts it.

scan_results="$(stat -f -L -c %T /root/agent/scan_results)"
target_files="$(stat -f -L -c %T /root/agent/target_files)"

if [ "$scan_results" != "nfs" ]
then
    echo "[+] mounting scan_results"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/master/scan_results /root/agent/scan_results
fi

if [ "$target_files" != "nfs" ]
then
    echo "[+] mounting target_files"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/master/target_files /root/agent/target_files
fi
