#include <arpa/inet.h>
#define IPV4_STR_LEN 16

/**
 * clears the erros of the socket and prepares for closing
 * @param fd the file descriptor
 * @return the socket state
 */
int getSO_ERROR(int fd);

void sockaddr_to_host(struct sockaddr_in sockaddr, char* host);