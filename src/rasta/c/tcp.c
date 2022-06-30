#include <stdio.h>
#include <string.h> //memset
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "tcp.h"
#include "rmemory.h"
#include "bsd_utils.h"

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

int tcp_init()
{
    return bsd_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void tcp_bind(int file_descriptor, uint16_t port)
{
    bsd_bind_port(file_descriptor, port);
}

void tcp_bind_device(int file_descriptor, uint16_t port, char *ip)
{
    bsd_bind_device(file_descriptor, port, ip);
}

void tcp_listen(int file_descriptor)
{
    if (listen(file_descriptor, MAX_PENDING_CONNECTIONS) < 0)
    {
        // listen failed
        perror("error whe listening to file_descriptor " + file_descriptor);
        exit(1);
    }
}

int tcp_accept(int file_descriptor, struct sockaddr_in *sender)
{
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    int socket;
    if ((socket = accept(file_descriptor, (struct sockaddr *)sender, &sender_len)) < 0)
    {
        perror("tcp failed to accept connection");
        exit(1);
    }
    return socket;
}

void tcp_connect(int file_descriptor, char *host, uint16_t port)
{
    struct sockaddr_in server;

    rmemset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // convert host string to usable format
    if (inet_aton(host, &server.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    if (connect(file_descriptor, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("tcp connection failed");
        exit(1);
    }
}

size_t tcp_receive(int file_descriptor, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
{
    ssize_t recv_len;
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);

    // wait for incoming data
    if ((recv_len = recvfrom(file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) < 0)
    {
        perror("an error occured while trying to receive data");
        exit(1);
    }

    return (size_t)recv_len;
}

void tcp_send(int file_descriptor, unsigned char *message, size_t message_len, char *host, uint16_t port)
{
    bsd_send(file_descriptor, message, message_len, host, port);
}

void tcp_close(int file_descriptor)
{
    bsd_close(file_descriptor);
}
