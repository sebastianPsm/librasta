#include <arpa/inet.h>
#include <errno.h>
#include <rasta/bsd_utils.h>
#include <rasta/rmemory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset
#include <unistd.h>

#include "transport.h"
#include "tcp.h"

void tcp_init(rasta_transport_socket *transport_state, const rasta_config_tls *tls_config) {
    transport_state->tls_config = tls_config;
    transport_state->file_descriptor = bsd_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static void apply_tls_mode(rasta_transport_socket *transport_state) {
    const rasta_config_tls *tls_config = transport_state->tls_config;
    switch (tls_config->mode) {
    case TLS_MODE_DISABLED:
        transport_state->activeMode = TLS_MODE_DISABLED;
        break;
    default:
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        abort();
    }
}

static void handle_tls_mode_server(rasta_transport_socket *transport_state) {
    apply_tls_mode(transport_state);
}

void tcp_bind(rasta_transport_socket *transport_state, uint16_t port) {
    bsd_bind_port(transport_state->file_descriptor, port);
}

void tcp_bind_device(rasta_transport_socket *transport_state, const char *ip, uint16_t port) {
    bsd_bind_device(transport_state->file_descriptor, port, ip);
}

void tcp_listen(rasta_transport_socket *transport_state) {
    if (listen(transport_state->file_descriptor, MAX_PENDING_CONNECTIONS) < 0) {
        // listen failed
        fprintf(stderr, "error when listening to file_descriptor %d", transport_state->file_descriptor);
        abort();
    }

    handle_tls_mode_server(transport_state);
}

int tcp_accept(rasta_transport_socket *transport_state) {
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    int socket;
    if ((socket = accept(transport_state->file_descriptor, (struct sockaddr *)&empty_sockaddr_in, &sender_len)) < 0) {
        perror("tcp failed to accept connection");
        abort();
    }

    return socket;
}

int tcp_connect(rasta_transport_channel *channel) {
    struct sockaddr_in server;

    rmemset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(channel->remote_port);

    // convert host string to usable format
    if (inet_aton(channel->remote_ip_address, &server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        abort();
    }

    if (connect(channel->fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        channel->connected = false;
        return 1;
    }

    channel->connected = true;
    return 0;
}

ssize_t tcp_receive(rasta_transport_channel *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    if (transport_state->tls_mode == TLS_MODE_DISABLED) {
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(transport_state->fd, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) < 0) {
            perror("an error occured while trying to receive data");
            return -1;
        }

        return (size_t)recv_len;
    }
    return 0;
}

void tcp_send(rasta_transport_channel *transport_state, unsigned char *message, size_t message_len) {
    if (send(transport_state->fd, message, message_len, 0) < 0) {
        perror("failed to send data");
        abort();
    }
}

void tcp_close(rasta_transport_channel *transport_state) {
    bsd_close(transport_state->fd);
}

void transport_listen(rasta_transport_socket *socket) {
    tcp_listen(socket);
}

void transport_accept(rasta_transport_socket *socket, rasta_transport_channel* channel) {
    int fd = tcp_accept(socket);
    channel->id = socket->id;
    channel->remote_port = 0;
    channel->remote_ip_address = NULL;
    channel->send_callback = send_callback;
    channel->tls_mode = socket->activeMode;
    channel->fd = fd;
    channel->connected = true;

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_size) != 0) {
        perror("tcp failed to resolve peer name");
        abort();
    }

    channel->remote_ip_address = rmalloc(sizeof(char) * 20);
    strcpy(channel->remote_ip_address, inet_ntoa(addr.sin_addr));
    channel->remote_port = ntohs(addr.sin_port);
}

int transport_connect(rasta_transport_socket *socket, rasta_transport_channel *channel, char *host, uint16_t port) {
    channel->id = socket->id;
    channel->remote_port = port;
    channel->remote_ip_address = rmalloc(sizeof(char) * 15);
    channel->send_callback = send_callback;
    rmemcpy(channel->remote_ip_address, host, 15);
    channel->tls_mode = socket->activeMode;
    channel->fd = socket->file_descriptor;
    return tcp_connect(channel);
}

int transport_redial(rasta_transport_channel* channel) {
    return tcp_connect(channel);
}

void transport_close(rasta_transport_channel *channel) {
    if (channel->connected) {
        bsd_close(channel->fd);
    }
}

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    UNUSED(mux);
    UNUSED(channel_index);
    tcp_send(channel, data_to_send.bytes, data_to_send.length);
}

ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    UNUSED(mux);
    // TODO: exchange MAX_DEFER_QUEUE_MSG_SIZE by something depending on send_max (i.e. the receive buffer size)
    // search for connected_recv_buffer_size
    // TODO: Manage possible remaining data in the receive buffer on next call to rasta_recv
    return tcp_receive(data->channel, buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void transport_create_socket(rasta_transport_socket *socket, int id, const rasta_config_tls *tls_config) {
    // init socket
    socket->id = id;
    tcp_init(socket, tls_config);
}

void transport_bind(rasta_transport_socket *socket, const char *ip, uint16_t port) {
    tcp_bind_device(socket, ip, port);
}
