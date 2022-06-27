#include "udp.h"
#include "bsd_utils.h"

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif


int udp_init()
{
    return bsd_create_socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP);
}

void udp_bind(int file_descriptor, uint16_t port)
{
    bsd_bind_port(file_descriptor, port);
}

void udp_bind_device(int file_descriptor, uint16_t port, char *ip)
{
    bsd_bind_device(file_descriptor, port, ip);
}

size_t udp_receive(int file_descriptor, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
{
    return bsd_receive(file_descriptor, received_message, max_buffer_len, sender);
}

void udp_send(int file_descriptor, unsigned char *message, size_t message_len, char *host, uint16_t port)
{
    bsd_send(file_descriptor, message, message_len, host, port);
}

void udp_close(int file_descriptor)
{
    bsd_close(file_descriptor);
}

