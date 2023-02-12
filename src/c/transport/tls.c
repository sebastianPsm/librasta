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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfio.h>

#include <rasta/ssl_utils.h>

#ifndef WOLFSSL_SSLKEYLOGFILE_OUTPUT
#define WOLFSSL_SSLKEYLOGFILE_OUTPUT "sslkeylog.log"
#endif

#ifdef WOLFSSL_SET_TLS13_SECRET_CB_EXISTS
/* Callback function for TLS v1.3 secrets for use with Wireshark */
static int Tls13SecretCallback(WOLFSSL *ssl, int id, const unsigned char *secret,
                               int secretSz, void *ctx) {
    int i;
    const char *str = NULL;
    unsigned char clientRandom[32];
    int clientRandomSz;
    XFILE fp = stderr;
    if (ctx) {
        fp = XFOPEN((const char *)ctx, "ab");
        if (fp == XBADFILE) {
            return BAD_FUNC_ARG;
        }
    }

    clientRandomSz = (int)wolfSSL_get_client_random(ssl, clientRandom,
                                                    sizeof(clientRandom));

    if (clientRandomSz <= 0) {
        printf("Error getting client random %d\n", clientRandomSz);
    }

#if 0
    printf("TLS Client Secret CB: Rand %d, Secret %d\n",
        clientRandomSz, secretSz);
#endif

    switch (id) {
    case CLIENT_EARLY_TRAFFIC_SECRET:
        str = "CLIENT_EARLY_TRAFFIC_SECRET";
        break;
    case EARLY_EXPORTER_SECRET:
        str = "EARLY_EXPORTER_SECRET";
        break;
    case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
        str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
        break;
    case SERVER_HANDSHAKE_TRAFFIC_SECRET:
        str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
        break;
    case CLIENT_TRAFFIC_SECRET:
        str = "CLIENT_TRAFFIC_SECRET_0";
        break;
    case SERVER_TRAFFIC_SECRET:
        str = "SERVER_TRAFFIC_SECRET_0";
        break;
    case EXPORTER_SECRET:
        str = "EXPORTER_SECRET";
        break;
    default:
        break;
    }

    if (str != NULL) {
        fprintf(fp, "%s ", str);
    }
    for (i = 0; i < clientRandomSz; i++) {
        fprintf(fp, "%02x", clientRandom[i]);
    }
    fprintf(fp, " ");
    for (i = 0; i < secretSz; i++) {
        fprintf(fp, "%02x", secret[i]);
    }
    fprintf(fp, "\n");

    if (fp != stderr) {
        XFCLOSE(fp);
    }

    return 0;
}
#endif

void tcp_init(rasta_transport_connection *transport_state, const struct RastaConfigTLS *tls_config) {
    transport_state->tls_config = tls_config;
    transport_state->file_descriptor = bsd_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static void apply_tls_mode(rasta_transport_connection *transport_state) {
    const struct RastaConfigTLS *tls_config = transport_state->tls_config;
    switch (tls_config->mode) {
    case TLS_MODE_DISABLED:
        transport_state->activeMode = TLS_MODE_DISABLED;
        break;
    case TLS_MODE_TLS_1_3:
        transport_state->activeMode = TLS_MODE_TLS_1_3;
        break;
    default:
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        abort();
    }
}

static void handle_tls_mode_server(rasta_transport_connection *transport_state) {
    apply_tls_mode(transport_state);
    if (transport_state->activeMode == TLS_MODE_TLS_1_3) {
        wolfssl_start_tls_server(transport_state, transport_state->tls_config);
    }
}

static void handle_tls_mode_client(rasta_transport_connection *transport_state) {
    apply_tls_mode(transport_state);
    if (transport_state->activeMode == TLS_MODE_TLS_1_3) {
        wolfssl_start_tls_client(transport_state, transport_state->tls_config);
    }
}

void tcp_bind(rasta_transport_connection *transport_state, uint16_t port) {
    bsd_bind_port(transport_state->file_descriptor, port);
}

void tcp_bind_device(rasta_transport_connection *transport_state, uint16_t port, char *ip) {
    bsd_bind_device(transport_state->file_descriptor, port, ip);
}

void tcp_listen(rasta_transport_connection *transport_state) {
    if (listen(transport_state->file_descriptor, MAX_PENDING_CONNECTIONS) < 0) {
        // listen failed
        fprintf(stderr, "error whe listening to file_descriptor %d", transport_state->file_descriptor);
        abort();
    }

    handle_tls_mode_server(transport_state);
}

int tcp_accept(rasta_transport_connection *transport_state) {
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    int socket;
    if ((socket = accept(transport_state->file_descriptor, (struct sockaddr *)&empty_sockaddr_in, &sender_len)) < 0) {
        perror("tcp failed to accept connection");
        abort();
    }

    return socket;
}

void tcp_accept_tls(rasta_transport_connection *transport_state, struct rasta_connected_transport_channel_state *connectionState) {
    int socket = tcp_accept(transport_state);

    /* Create a WOLFSSL object */
    if ((connectionState->ssl = wolfSSL_new(transport_state->ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        abort();
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(connectionState->ssl, socket);
    connectionState->tls_state = RASTA_TLS_CONNECTION_READY;

    /* Establish TLS connection */
    int ret = wolfSSL_accept(connectionState->ssl);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_accept error = %d\n",
                wolfSSL_get_error(connectionState->ssl, ret));
        abort();
    }

    tls_pin_certificate(connectionState->ssl, connectionState->tls_config->peer_tls_cert_path);

    set_tls_async(socket, connectionState->ssl);
    connectionState->file_descriptor = socket;
}

void tcp_connect(rasta_transport_connection *transport_state, char *host, uint16_t port) {
    struct sockaddr_in server;

    rmemset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // convert host string to usable format
    if (inet_aton(host, &server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        abort();
    }

    if (connect(transport_state->file_descriptor, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("tcp connection failed");
        abort();
    }

    if (transport_state->ctx == NULL) {
        handle_tls_mode_client(transport_state);
    }

    transport_state->ssl = wolfSSL_new(transport_state->ctx);
    if (!transport_state->ssl) {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(transport_state->ssl, 0));
        fprintf(stderr, "Error allocating WolfSSL session: %s.\n", error_str);
        abort();
    }

    if (transport_state->tls_config->tls_hostname[0]) {
        int ret = wolfSSL_check_domain_name(transport_state->ssl, transport_state->tls_config->tls_hostname);
        if (ret != SSL_SUCCESS) {
            fprintf(stderr, "Could not add domain name check for domain %s: %d", transport_state->tls_config->tls_hostname, ret);
            abort();
        }
    } else {
        fprintf(stderr, "No TLS hostname specified. Will accept ANY valid TLS certificate. Double-check configuration file.\n");
    }
    /* Attach wolfSSL to the socket */
    if (wolfSSL_set_fd(transport_state->ssl, transport_state->file_descriptor) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        abort();
    }

    /* required for getting random used */
    wolfSSL_KeepArrays(transport_state->ssl);
#ifdef WOLFSSL_SET_TLS13_SECRET_CB_EXISTS
    /* optional logging for wireshark */
    char* sslkeylogfile_path = getenv("TLS_SECRET_LOGFILE_PATH");
    if (sslkeylogfile_path == NULL) {
        wolfSSL_set_tls13_secret_cb(transport_state->ssl, Tls13SecretCallback,
                                    (void *)WOLFSSL_SSLKEYLOGFILE_OUTPUT);
    } else {
        wolfSSL_set_tls13_secret_cb(transport_state->ssl, Tls13SecretCallback,
                                    sslkeylogfile_path);
    }
#endif
    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(transport_state->ssl) != WOLFSSL_SUCCESS) {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(transport_state->ssl, 0));
        fprintf(stderr, "ERROR: failed to connect to wolfSSL %s.\n", error_str);
        abort();
    }

    tls_pin_certificate(transport_state->ssl, transport_state->tls_config->peer_tls_cert_path);

    wolfSSL_FreeArrays(transport_state->ssl);
    set_tls_async(transport_state->file_descriptor, transport_state->ssl);
}

ssize_t tls_receive(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    // TODO how do we determine the sender?
    (void)sender;
    return wolfssl_receive_tls(ssl, received_message, max_buffer_len);
}

void tls_send(WOLFSSL *ssl, unsigned char *message, size_t message_len) {
    wolfssl_send_tls(ssl, message, message_len);
}

void tcp_close(rasta_transport_connection *transport_state) {
    if (transport_state->activeMode != TLS_MODE_DISABLED) {
        wolfssl_cleanup(transport_state);
    }

    bsd_close(transport_state->file_descriptor);
}

void transport_connect(redundancy_mux *mux, unsigned int channel, char *host, uint16_t port) {
    // init socket
    tcp_init(&mux->transport_sockets[channel], &mux->config.tls);
    tcp_bind_device(&mux->transport_sockets[channel],
                    (uint16_t)mux->config.redundancy.connections.data[channel].port,
                    mux->config.redundancy.connections.data[channel].ip);
    tcp_connect(&mux->transport_sockets[channel], host, port);
}

void transport_close(rasta_transport_channel *channel) {
    bsd_close(channel->fd);
    if (channel->ssl) {
        wolfSSL_shutdown(channel->ssl);
        wolfSSL_free(channel->ssl);
    }
}

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    UNUSED(mux);
    UNUSED(channel_index);
    tls_send(channel->ssl, data_to_send.bytes, data_to_send.length);
}

ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    UNUSED(mux);
    return tls_receive(data->ssl, buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void transport_initialize(rasta_transport_channel *channel, rasta_transport_connection transport_state, char *ip, uint16_t port) {
    channel->fd = transport_state.file_descriptor;
    channel->ssl = transport_state.ssl;

    channel->remote_port = port;
    channel->remote_ip_address = rmalloc(sizeof(char) * 15);
    channel->send_callback = send_callback;
    rmemcpy(channel->remote_ip_address, ip, 15);
}
