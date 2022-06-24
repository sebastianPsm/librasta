#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include "bsd_utils.h"


int getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        exit(1);
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}

void sockaddr_to_host(struct sockaddr_in sockaddr, char* host){
    inet_ntop(AF_INET, &(sockaddr.sin_addr), host, IPV4_STR_LEN);
}