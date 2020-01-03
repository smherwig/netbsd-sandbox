Overview
========
The secmodel_sandbox security module for NetBSD 7.x.  The module allows an
application to set application-specific, dynamic
[kauth](https://netbsd.gw.com/cgi-bin/man-cgi?kauth++NetBSD-7.1) rules.
The rules are specific in Lua, and interpreted by using NetBSD's [in-kernel Lua
interpreter](https://netbsd.gw.com/cgi-bin/man-cgi?intro+9lua+NetBSD-7.1)

I presented this work at [BSDCan 2017](https://www.bsdcan.org/2017/schedule/events/835.en.html)


Building
========

I assume the NetBSD sources are located at `/usr/src`.

```
git clone https://github.com/smherwig/netbsd-sandbox
cp -r netbsd-sandbox/secmodel_sandbox /usr/src/sys/modules
```

The easiest way to build only the `secmodel_sandbox` and `lua` kernel modules
are to edit `/usr/src/sys/modules/Makefile`:

```
cd /usr/src/sys/modules

# make a backup of the original
cp Makefile Makefile.orig
```

Now, edit `Makefile` to look like:

```
.include <bsd.own.mk>

SUBDIR= secmodel_sandbox
SUBDIR+= lua
```

In order to build the two kernel modules, enter:

```
cd /usr/src
./build.sh -T ../out/tool -D ../out/dest -R ../out/release -O ../out/obj -U -u -m amd64 modules
```

If the build is successful, the modules are located under
`/usr/out/dest/stand/amd64/7.0/modules`.


Loading and Unloading
=====================

The following script loads the `secmodel_sandbox` kernel module and its `lua`
mdoule dependency, and setups up the device file.

```
#!/bin/sh

cd /usr/out/dest/stand/amd64/7.0/modules
sudo modload ./lua.kmod
sudo modload ./secmodel_sandbox.kmod

if [ -e /dev/sandbox ]; then
    sudo rm /dev/sandbox
fi

major=`mknod -l | grep 'sandbox' | awk '{print $4}'`
sudo mknod -u root -g wheel -m 660 /dev/sandbox c $major 0
```

This script unloads the two kernel modules and remove the sandbox module's
device file:

```
#!/bin/sh 

sudo modunload secmodel_sandbox
sudo modunload lua
sudo rm /dev/sandbox
```


