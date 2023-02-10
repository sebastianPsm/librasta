
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset
#include <unistd.h>

#include <rasta/bsd_utils.h>
#include <rasta/rmemory.h>
#include <rasta/udp.h>

#include "transport.h"

#define MAX_WARNING_LENGTH_BYTES 128

static void handle_port_unavailable(const uint16_t port) {
    const char *warning_format = "could not bind the socket to port %d";
    char warning_mbuf[MAX_WARNING_LENGTH_BYTES + 1];
    snprintf(warning_mbuf, MAX_WARNING_LENGTH_BYTES, warning_format, port);

    // bind failed
    perror("warning_mbuf");
    exit(1);
}

static void handle_tls_mode(rasta_transport_connection *transport_state) {
    const struct RastaConfigTLS *tls_config = transport_state->tls_config;
    switch (tls_config->mode) {
    case TLS_MODE_DISABLED: {
        transport_state->activeMode = TLS_MODE_DISABLED;
        break;
    }
    default: {
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        exit(1);
    }
    }
}

void udp_bind(rasta_transport_connection *transport_state, uint16_t port) {
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    // bind socket to port
    if (bind(transport_state->file_descriptor, (struct sockaddr *)&local, sizeof(local)) == -1) {
        handle_port_unavailable(port);
    }
    handle_tls_mode(transport_state);
}

void udp_bind_device(rasta_transport_connection *transport_state, uint16_t port, char *ip) {
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *)&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = inet_addr(ip);

    // bind socket to port
    if (bind(transport_state->file_descriptor, (struct sockaddr *)&local, sizeof(struct sockaddr_in)) == -1) {
        // bind failed
        handle_port_unavailable(port);
        exit(1);
    }
    handle_tls_mode(transport_state);
}

void udp_close(rasta_transport_connection *transport_state) {
    int file_descriptor = transport_state->file_descriptor;
    if (file_descriptor >= 0) {
        getSO_ERROR(file_descriptor);                   // first clear any errors, which can cause close to fail
        if (shutdown(file_descriptor, SHUT_RDWR) < 0)   // secondly, terminate the 'reliable' delivery
            if (errno != ENOTCONN && errno != EINVAL) { // SGI causes EINVAL
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

size_t udp_receive(rasta_transport_connection *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    if (transport_state->activeMode == TLS_MODE_DISABLED) {
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(transport_state->file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) == -1) {
            perror("an error occured while trying to receive data");
            exit(1);
        }

        return (size_t)recv_len;
    }
    return 0;
}

void udp_send(rasta_transport_connection *transport_state, unsigned char *message, size_t message_len, char *host, uint16_t port) {
    struct sockaddr_in receiver = host_port_to_sockaddr(host, port);
    if (transport_state->activeMode == TLS_MODE_DISABLED) {

        // send the message using the other send function
        udp_send_sockaddr(transport_state, message, message_len, receiver);
    }
}

void udp_send_sockaddr(rasta_transport_connection *transport_state, unsigned char *message, size_t message_len, struct sockaddr_in receiver) {
    if (transport_state->activeMode == TLS_MODE_DISABLED) {
        if (sendto(transport_state->file_descriptor, message, message_len, 0, (struct sockaddr *)&receiver, sizeof(receiver)) ==
            -1) {
            perror("failed to send data");
            exit(1);
        }
    }
}

void udp_init(rasta_transport_connection *transport_state, const struct RastaConfigTLS *tls_config) {
    // the file descriptor of the socket
    int file_desc;

    transport_state->tls_config = tls_config;

    // create a udp socket
    if ((file_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        // creation failed, exit
        perror("The udp socket could not be initialized");
        exit(1);
    }
    transport_state->file_descriptor = file_desc;
}

void transport_create_socket() {
    // init and bind sockets
    udp_init(&mux->transport_sockets[i], &mux->config.tls);
    udp_bind(&mux->transport_sockets[i], (uint16_t)mux->config.redundancy.connections.data[i].port);
}

void transport_connect(redundancy_mux *mux, unsigned int channel, char *host, uint16_t port) {
    (void)mux; (void)channel; (void)host; (void) port;
}

void transport_close(rasta_transport_channel *channel) {
    (void)channel;
}

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    udp_send(&mux->transport_sockets[channel_index], data_to_send.bytes, data_to_send.length, channel->ip_address, channel->port);
}

ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    return udp_receive(&mux->transport_sockets[data->channel_index], buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void transport_initialize(rasta_transport_channel *channel, rasta_transport_connection transport_state, char *ip, uint16_t port) {
    (void)transport_state;
    channel->port = port;
    channel->ip_address = rmalloc(sizeof(char) * 15);
    channel->send_callback = send_callback;
    rmemcpy(channel->ip_address, ip, 15);
}
