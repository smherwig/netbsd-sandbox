#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "sandbox.h"

int main(int argc, char *argv[])
{
    int error = 0;
    int fd = -1;
    int version = 0;
    int nlists = 0;

    fd = open("/dev/sandbox", O_RDWR);
    if (fd == - 1)
        goto fail;

    error = ioctl(fd, SANDBOX_IOC_VERSION, &version);
    if (error == -1)
        goto fail;

    error = ioctl(fd, SANDBOX_IOC_NLISTS, &nlists);
    if (error == -1)
        goto fail;

    printf("version=%d, nlists=%d\n", version, nlists);

    (void)close(fd);

    goto succeed;

fail:
    error = 1;
succeed:
    return (error);
}

