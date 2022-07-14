#include <stdlib.h>
#include <stdio.h>
#include <string.h> //memset
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "rmemory.h"
#include "bsd_utils.h"

int bsd_create_socket(int family, int type, int protocol_type)
{
    // the file descriptor of the socket
    int file_desc;

    // create a tcp socket
    if ((file_desc = socket(family, type, protocol_type)) < 0)
    {
        // creation failed, exit
        if (type == IPPROTO_UDP)
        {
            perror("The udp socket could not be initialized");
        }
        else if (type == IPPROTO_TCP)
        {
            perror("The tcp socket could not be initialized");
        }
        else
        {
            perror("The socket could not be initialized");
        }

        exit(1);
    }

    return file_desc;
}

void bsd_bind_port(int file_descriptor, uint16_t port)
{
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    int yes = 1;
    if (setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    // bind socket to port
    if (bind(file_descriptor, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        // bind failed
        perror("could not bind the socket to port " + port);
        exit(1);
    }
}

void bsd_bind_device(int file_descriptor, uint16_t port, char *ip)
{
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = inet_addr(ip);

    int yes = 1;
    if (setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    // bind socket to port
    if (bind(file_descriptor, (struct sockaddr *)&local, sizeof(struct sockaddr_in)) < 0)
    {
        // bind failed
        perror("could not bind the socket to port");
        exit(1);
    }
}

size_t bsd_receive(int file_descriptor, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
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

void bsd_send(int file_descriptor, unsigned char *message, size_t message_len, char *host, uint16_t port)
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
    bsd_send_sockaddr(file_descriptor, message, message_len, receiver);
}

void bsd_send_sockaddr(int file_descriptor, unsigned char *message, size_t message_len, struct sockaddr_in receiver)
{
    if (sendto(file_descriptor, message, message_len, 0, (struct sockaddr *)&receiver, sizeof(receiver)) < 0)
    {
        perror("failed to send data");
        exit(1);
    }
}

void bsd_close(int file_descriptor)
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

int getSO_ERROR(int fd)
{
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        exit(1);
    if (err)
        errno = err; // set errno to the socket SO_ERROR
    return err;
}

void sockaddr_to_host(struct sockaddr_in sockaddr, char *host)
{
    inet_ntop(AF_INET, &(sockaddr.sin_addr), host, IPV4_STR_LEN);
}

struct sockaddr_in host_port_to_sockaddr(const char *host, uint16_t port)
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
    return receiver;
}
