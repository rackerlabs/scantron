#!/bin/bash


# Install python3-pip.
echo "[*] Installing pip3"
apt update
apt install python3-pip -y

# Install Ansible with pip.
echo "[*] Install ansible >=2.4.0.0 using pip"
pip3 install ansible\>=2.4.0.0

# Generate a passphrase-less SSH key pair for the autossh user.
echo "[*] Generating a passphrase-less SSH key pair for the autossh user"
ssh-keygen -b 4096 -t rsa -f autossh -q -N ""

# Move public key to the respective location for Ansible.
echo "[*] Move public SSH key to the Agent's ansible role."
mv autossh.pub ansible-playbooks/roles/agent/files/autossh.pub

# Move and rename private key to the respective location for Ansible.
echo "[*] Move private SSH key to the Master's ansible role."
mv autossh master/autossh.key

# Create empty scantron_secrets.json from scantron_secrets.json.empty.
cp master/scantron_secrets.json.empty master/scantron_secrets.json
