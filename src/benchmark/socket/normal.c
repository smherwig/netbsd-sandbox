#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int 
main(int argc, char *argv[])
{
    int s = 0;
    int i = 0;
    int n = 0;

    if (argc != 2) {
        fprintf(stderr, "%s <num-iterations>\n", argv[0]);
        exit(1);
    }

    n = atoi(argv[1]);

    for (i = 0; i < n; i++) {
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        close(s);
    }

    return (0);
}
