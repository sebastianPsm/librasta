#include <arpa/inet.h>
#include <errno.h>
#include <rasta/bsd_utils.h>
#include <rasta/rmemory.h>
#include <rasta/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset
#include <unistd.h>

#include "transport.h"

void tcp_init(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
    transport_state->tls_config = tls_config;
    transport_state->file_descriptor = bsd_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static void apply_tls_mode(struct rasta_transport_state *transport_state) {
    const struct RastaConfigTLS *tls_config = transport_state->tls_config;
    switch (tls_config->mode) {
    case TLS_MODE_DISABLED:
        transport_state->activeMode = TLS_MODE_DISABLED;
        break;
    default:
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        exit(1);
    }
}

static void handle_tls_mode_server(struct rasta_transport_state *transport_state) {
    apply_tls_mode(transport_state);
}

void tcp_bind(struct rasta_transport_state *transport_state, uint16_t port) {
    bsd_bind_port(transport_state->file_descriptor, port);
}

void tcp_bind_device(struct rasta_transport_state *transport_state, uint16_t port, char *ip) {
    bsd_bind_device(transport_state->file_descriptor, port, ip);
}

void tcp_listen(struct rasta_transport_state *transport_state) {
    if (listen(transport_state->file_descriptor, MAX_PENDING_CONNECTIONS) < 0) {
        // listen failed
        fprintf(stderr, "error whe listening to file_descriptor %d", transport_state->file_descriptor);
        exit(1);
    }

    handle_tls_mode_server(transport_state);
}

int tcp_accept(struct rasta_transport_state *transport_state) {
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    int socket;
    if ((socket = accept(transport_state->file_descriptor, (struct sockaddr *)&empty_sockaddr_in, &sender_len)) < 0) {
        perror("tcp failed to accept connection");
        exit(1);
    }

    return socket;
}

void tcp_connect(struct rasta_transport_state *transport_state, char *host, uint16_t port) {
    struct sockaddr_in server;

    rmemset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // convert host string to usable format
    if (inet_aton(host, &server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    if (connect(transport_state->file_descriptor, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("tcp connection failed");
        exit(1);
    }
}

ssize_t tcp_receive(struct rasta_transport_state *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    if (transport_state->activeMode == TLS_MODE_DISABLED) {
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(transport_state->file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) < 0) {
            perror("an error occured while trying to receive data");
            return -1;
        }

        return (size_t)recv_len;
    }
    return 0;
}

void tcp_send(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, char *host, uint16_t port) {
    bsd_send(transport_state->file_descriptor, message, message_len, host, port);
}

void tcp_close(struct rasta_transport_state *transport_state) {
    bsd_close(transport_state->file_descriptor);
}

void transport_connect(redundancy_mux *mux, unsigned int channel, char *host, uint16_t port) {
    // init socket
    tcp_init(&mux->transport_states[channel], &mux->config.tls);
    tcp_bind_device(&mux->transport_states[channel],
                    (uint16_t)mux->config.redundancy.connections.data[channel].port,
                    mux->config.redundancy.connections.data[channel].ip);
    tcp_connect(&mux->transport_states[channel], host, port);
}

void transport_reconnect(redundancy_mux *mux, unsigned int channel) {
    (void)mux; (void)channel;
    // tcp_connect(&mux->transport_states[channel], host, port);
}

void transport_close(rasta_transport_channel *channel) {
    bsd_close(channel->fd);
}

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    UNUSED(channel_index);
    tcp_send(&mux->transport_states[channel_index], data_to_send.bytes, data_to_send.length, channel->ip_address, channel->port);
}

ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    return tcp_receive(&mux->transport_states[data->channel_index], buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data) {
    channel->fd = data->event->fd;
}

void transport_initialize(rasta_transport_channel *channel, struct rasta_transport_state transport_state, char *ip, uint16_t port) {
    channel->fd = transport_state.file_descriptor;

    channel->port = port;
    channel->ip_address = rmalloc(sizeof(char) * 15);
    channel->send_callback = send_callback;
    rmemcpy(channel->ip_address, ip, 15);
}
