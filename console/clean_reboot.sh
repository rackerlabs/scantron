#!/bin/bash

killall autossh
killall ssh

systemctl status nginx --no-pager 
systemctl stop nginx
systemctl status nginx --no-pager 

systemctl status uwsgi --no-pager 
systemctl stop uwsgi
systemctl status uwsgi --no-pager 

systemctl status nfs-kernel-server --no-pager 
systemctl stop nfs-kernel-server
systemctl status nfs-kernel-server --no-pager 

echo Sleeping 5 seconds before rebooting.
sleep 5

reboot

