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

# Move public key to the respective locations for Ansible.
echo "[*] Copying public SSH key to the console's ansible role (ansible-playbooks/roles/console/files/autossh.pub)"
cp autossh.pub ansible-playbooks/roles/console/files/autossh.pub
echo "[*] Moving public SSH key to the engine's ansible role (ansible-playbooks/roles/engine/files/autossh.pub)"
mv autossh.pub ansible-playbooks/roles/engine/files/autossh.pub

# Place private key to the respective locations for Ansible.
echo "[*] Copying private SSH key to the engine's ansible role (engine/autossh.key)"
cp autossh engine/autossh.key
echo "[*] Moving private SSH key to the console's ansible role (console/autossh.key)"
mv autossh console/autossh.key

# Create empty scantron_secrets.json from scantron_secrets.json.empty.
cp console/scantron_secrets.json.empty console/scantron_secrets.json

# Generate random Django key.
# https://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
echo "[*] Generating a random Django Key, database, and user passwords."

if [[ `uname` == "Darwin" ]]
then
   # Locale needs to be set for OSX, else tr responds with "tr: Illegal byte sequence".
   # https://unix.stackexchange.com/questions/45404/why-cant-tr-read-from-dev-urandom-on-osx
   DJANGO_KEY=`< /dev/urandom LC_ALL=C tr -dc _A-Z-a-z-0-9 | head -c${1:-64};echo;`
   DATABASE_PASSWORD=`< /dev/urandom LC_ALL=C tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`
   DJANGO_SUPER_USER_PASSWORD=`< /dev/urandom LC_ALL=C tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`
   DJANGO_USER_PASSWORD=`< /dev/urandom LC_ALL=C tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`

   # -i requires additional arguments on OSX, else it responds with "sed: 1: "<filename>": invalid command code".
   # https://markhneedham.com/blog/2011/01/14/sed-sed-1-invalid-command-code-r-on-mac-os-x/
   sed -i "" "s/REPLACE_THIS_DJANGO_KEY/$DJANGO_KEY/g" console/scantron_secrets.json
   sed -i "" "s/REPLACE_THIS_DATABASE_PASSWORD/$DATABASE_PASSWORD/g" console/scantron_secrets.json
   sed -i "" "s/REPLACE_THIS_DJANGO_SUPER_USER_PASSWORD/$DJANGO_SUPER_USER_PASSWORD/g" console/scantron_secrets.json
   sed -i "" "s/REPLACE_THIS_DJANGO_USER_PASSWORD/$DJANGO_USER_PASSWORD/g" console/scantron_secrets.json
else
   DJANGO_KEY=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-64};echo;`
   DATABASE_PASSWORD=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`
   DJANGO_SUPER_USER_PASSWORD=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`
   DJANGO_USER_PASSWORD=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;`

   sed -i "s/REPLACE_THIS_DJANGO_KEY/$DJANGO_KEY/g" console/scantron_secrets.json
   sed -i "s/REPLACE_THIS_DATABASE_PASSWORD/$DATABASE_PASSWORD/g" console/scantron_secrets.json
   sed -i "s/REPLACE_THIS_DJANGO_SUPER_USER_PASSWORD/$DJANGO_SUPER_USER_PASSWORD/g" console/scantron_secrets.json
   sed -i "s/REPLACE_THIS_DJANGO_USER_PASSWORD/$DJANGO_USER_PASSWORD/g" console/scantron_secrets.json
fi

echo "[+] Done!"
