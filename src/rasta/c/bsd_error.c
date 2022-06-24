#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>


int getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        exit(1);
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}