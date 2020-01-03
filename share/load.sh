#!/bin/sh

sudo modload ./lua.kmod
sudo modload ./secmodel_sandbox.kmod

if [ -e /dev/sandbox ]; then
    sudo rm /dev/sandbox
fi

major=`mknod -l | grep 'sandbox' | awk '{print $4}'`
sudo mknod -u root -g wheel -m 660 /dev/sandbox c $major 0

