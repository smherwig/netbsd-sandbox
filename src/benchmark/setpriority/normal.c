#include <sys/resource.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int 
main(int argc, char *argv[])
{
    int error = 0;
    int i = 0;
    int n = 0;
    int nice = 0;

    if (argc != 2) {
        fprintf(stderr, "%s <num-iterations>\n", argv[0]);
        exit(1);
    }

    n = atoi(argv[1]);

#if 0
    nice = getpriority(PRIO_PROCESS, 0);
    printf("nice: %d\n", nice);
#endif

    for (i = 0; i < n; i++) {
#if 0
        errno = 0;
#endif
        setpriority(PRIO_PROCESS, 0, 0);
#if 0
        if (error == -1 && errno != 0)
            perror("setpriority");
#endif
    }

    return (0);
}
