#include "tcp.h"
#include <stdio.h>
#include <string.h> //memset
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "rmemory.h"
#include "bsd_utils.h"

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

int tcp_init()
{
    // the file descriptor of the socket
    int file_desc;

    // create a tcp socket
    if ((file_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP)) < 0)
    {
        // creation failed, exit
        perror("The tcp socket could not be initialized");
        exit(1);
    }

    return file_desc;
}

void tcp_bind(int file_descriptor, uint16_t port)
{
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    // bind socket to port
    if (bind(file_descriptor, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        // bind failed
        perror("could not bind the socket to port " + port);
        exit(1);
    }
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

void tcp_bind_device(int file_descriptor, uint16_t port, char *ip)
{
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = inet_addr(ip);

    // bind socket to port
    if (bind(file_descriptor, (struct sockaddr *)&local, sizeof(struct sockaddr_in)) < 0)
    {
        // bind failed
        perror("could not bind the socket to port");
        exit(1);
    }
}

void tcp_close(int file_descriptor)
{
    // close(file_descriptor);
    if (file_descriptor >= 0)
    {
        getSO_ERROR(file_descriptor);                 // first clear any errors, which can cause close to fail
        if (shutdown(file_descriptor, SHUT_RDWR) < 0) // secondly, terminate the 'reliable' delivery
            if (errno != ENOTCONN && errno != EINVAL)
            { // SGI causes EINVAL
                perror("shutdown");
                exit(1);
            }
        if (close(file_descriptor) < 0) // finally call close()
        {
            perror("close");
            exit(1);
        }
    }
}

void tcp_accept(int file_descriptor, struct sockaddr_in *sender)
{
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    if (accept(file_descriptor, (struct sockaddr *)sender, &sender_len) < 0)
    {
        perror("tcp failed to accept connection");
        exit(1);
    }
}

void tcp_connect(int file_descriptor,  char *host, uint16_t port)
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
    struct sockaddr_in receiver;

    rmemset((char *)&receiver, 0, sizeof(receiver));
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons(port);

    // convert host string to usable format
    if (inet_aton(host, &receiver.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    // send the message using the other send function
    tcp_send_sockaddr(file_descriptor, message, message_len, receiver);
}

void tcp_send_sockaddr(int file_descriptor, unsigned char *message, size_t message_len, struct sockaddr_in receiver)
{
    if (sendto(file_descriptor, message, message_len, 0, (struct sockaddr *)&receiver, sizeof(receiver)) < 0)
    {
        perror("failed to send data");
        exit(1);
    }
}
