#!/bin/bash

# Make sure root doesn't run this script.
if [ "$(id -u)" == "0" ]; then
   echo "[-] Don't run this script as root!" 1>&2
   exit 1
fi

# Ensure pip3 is installed.
# https://stackoverflow.com/questions/592620/how-to-check-if-a-program-exists-from-a-bash-script
command -v pip3 >/dev/null 2>&1 || { echo >&2 "Script requires pip3 but it is not installed. \
Courtesy pastable: 'sudo apt update && sudo apt install python3-pip -y'"; exit 1; }

# Install Ansible with pip.
echo "[*] Install ansible >=2.4.0.0 using pip"
pip3 install ansible\>=2.4.0.0

# Generate a passphrase-less SSH key pair for the autossh user.
echo "[*] Generating a passphrase-less SSH key pair for the autossh user"
ssh-keygen -b 4096 -t rsa -f autossh -q -N ""

# Move public key to the respective location for Ansible.
echo "[*] Moving public SSH key to the Agent's ansible role (ansible-playbooks/roles/agent/files/autossh.pub)"
mv autossh.pub ansible-playbooks/roles/agent/files/autossh.pub

# Move and rename private key to the respective location for Ansible.
echo "[*] Moving private SSH key to the Master's ansible role (master/autossh.key)"
mv autossh master/autossh.key

# Create empty scantron_secrets.json from scantron_secrets.json.empty.
cp master/scantron_secrets.json.empty master/scantron_secrets.json
