#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sandbox.h"

static void 
usage(void)
{
    fprintf(stderr, 
            "usage: sandbox-exec [OPTION] script prog prog-args...\n"
            "\n"
            "  options:\n"
            "    -h\n"
            "      display this help message\n"
            "    -k\n"
            "      if process attempts a denied operation, kill the process\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    int error = 0;
    int c = 0;
    int flags = 0;

    opterr = 0;
    while ((c = getopt(argc, argv, "hk")) != -1) {
        switch (c) {
        case 'k':
            flags |= SANDBOX_ON_DENY_KILL;
            break;
        case 'h':
            usage();
        case '?':
            fprintf(stderr, "unknown option '%c'\n", (char)optopt);
            exit(1);
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 2)
        usage();

    error = sandbox_from_file(argv[0], flags);
    if (error == -1) {
        fprintf(stderr, "sandbox_from_file('%s') failed: '%s'\n", argv[0], strerror(errno));
        error = 1;
        goto fail;
    }

    error = execv(argv[1], &argv[1]);
    if (error == -1) {
        fprintf(stderr, "execv('%s', ...) failed: '%s'\n", argv[1], strerror(errno));
        error = 1;
        goto fail;
    }

fail:
    return (error);
}
