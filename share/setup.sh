#!/bin/sh

major=`mknod -l | grep 'sandbox' | awk '{print $4}'`
sudo mknod -u root -g wheel -m 660 /dev/sandbox c $major 0
