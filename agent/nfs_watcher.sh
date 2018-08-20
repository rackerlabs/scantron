#!/bin/bash

# Runs as a cronjob every minute.  If the NFS share is not established, re-mounts it.

nmap_results="$(stat -f -L -c %T /root/agent/nmap_results)"
target_files="$(stat -f -L -c %T /root/agent/target_files)"

if [ "$nmap_results" != "nfs" ]
then
    echo "[+] mounting nmap_results"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/master/nmap_results /root/agent/nmap_results
fi

if [ "$target_files" != "nfs" ]
then
    echo "[+] mounting target_files"
    mount -o rw,hard,noexec,tcp,port=2049 127.0.0.1:/home/scantron/master/target_files /root/agent/target_files
fi
