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

#ifdef ENABLE_TLS
#include <rasta/ssl_utils.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfio.h>
#endif

#ifdef ENABLE_TLS
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
#endif

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
#ifdef ENABLE_TLS
    case TLS_MODE_TLS_1_3:
        transport_state->activeMode = TLS_MODE_TLS_1_3;
        break;
#endif
    default:
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        exit(1);
    }
}

static void handle_tls_mode_server(struct rasta_transport_state *transport_state) {
    apply_tls_mode(transport_state);
#ifdef ENABLE_TLS
    if (transport_state->activeMode == TLS_MODE_TLS_1_3) {
        wolfssl_start_tls_server(transport_state, transport_state->tls_config);
    }
#endif
}

#ifdef ENABLE_TLS
static void handle_tls_mode_client(struct rasta_transport_state *transport_state) {
    apply_tls_mode(transport_state);
    if (transport_state->activeMode == TLS_MODE_TLS_1_3) {
        wolfssl_start_tls_client(transport_state, transport_state->tls_config);
    }
}
#endif

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

#ifdef ENABLE_TLS

void tcp_accept_tls(struct rasta_transport_state *transport_state, struct rasta_connected_transport_channel_state *connectionState) {
    int socket = tcp_accept(transport_state);

    /* Create a WOLFSSL object */
    if ((connectionState->ssl = wolfSSL_new(transport_state->ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        exit(1);
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(connectionState->ssl, socket);
    connectionState->tls_state = RASTA_TLS_CONNECTION_READY;

    /* Establish TLS connection */
    int ret = wolfSSL_accept(connectionState->ssl);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_accept error = %d\n",
                wolfSSL_get_error(connectionState->ssl, ret));
        exit(1);
    }

    tls_pin_certificate(connectionState->ssl, connectionState->tls_config->peer_tls_cert_path);

    set_tls_async(socket, connectionState->ssl);
    connectionState->file_descriptor = socket;
}
#endif

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

#ifdef ENABLE_TLS
    if (transport_state->ctx == NULL) {
        handle_tls_mode_client(transport_state);
    }

    transport_state->ssl = wolfSSL_new(transport_state->ctx);
    if (!transport_state->ssl) {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(transport_state->ssl, 0));
        fprintf(stderr, "Error allocating WolfSSL session: %s.\n", error_str);
        exit(1);
    }

    if (transport_state->tls_config->tls_hostname[0]) {
        int ret = wolfSSL_check_domain_name(transport_state->ssl, transport_state->tls_config->tls_hostname);
        if (ret != SSL_SUCCESS) {
            fprintf(stderr, "Could not add domain name check for domain %s: %d", transport_state->tls_config->tls_hostname, ret);
            exit(1);
        }
    } else {
        fprintf(stderr, "No TLS hostname specified. Will accept ANY valid TLS certificate. Double-check configuration file.");
    }
    /* Attach wolfSSL to the socket */
    if (wolfSSL_set_fd(transport_state->ssl, transport_state->file_descriptor) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        exit(1);
    }

    /* required for getting random used */
    wolfSSL_KeepArrays(transport_state->ssl);
#ifdef WOLFSSL_SET_TLS13_SECRET_CB_EXISTS
    /* optional logging for wireshark */
    wolfSSL_set_tls13_secret_cb(transport_state->ssl, Tls13SecretCallback,
                                (void *)WOLFSSL_SSLKEYLOGFILE_OUTPUT);
#endif
    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(transport_state->ssl) != WOLFSSL_SUCCESS) {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(transport_state->ssl, 0));
        fprintf(stderr, "ERROR: failed to connect to wolfSSL %s.\n", error_str);
        exit(1);
    }

    tls_pin_certificate(transport_state->ssl, transport_state->tls_config->peer_tls_cert_path);

    wolfSSL_FreeArrays(transport_state->ssl);
    set_tls_async(transport_state->file_descriptor, transport_state->ssl);
#endif
}
#ifdef ENABLE_TLS
ssize_t tls_receive(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    // TODO how do we determine the sender?
    (void)sender;
    return wolfssl_receive_tls(ssl, received_message, max_buffer_len);
}
#else
size_t tcp_receive(struct rasta_transport_state *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    if (transport_state->activeMode == TLS_MODE_DISABLED) {
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(transport_state->file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) < 0) {
            perror("an error occured while trying to receive data");
            exit(1);
        }

        return (size_t)recv_len;
    }
    return 0;
}
#endif

#ifdef USE_TCP
#ifdef ENABLE_TLS
void tls_send(WOLFSSL *ssl, unsigned char *message, size_t message_len) {
    wolfssl_send_tls(ssl, message, message_len);
}
#else
void tcp_send(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, char *host, uint16_t port) {
    bsd_send(transport_state->file_descriptor, message, message_len, host, port);
}
#endif
#endif

void tcp_close(struct rasta_transport_state *transport_state) {
#ifdef ENABLE_TLS
    if (transport_state->activeMode != TLS_MODE_DISABLED) {
        wolfssl_cleanup(transport_state);
    }
#endif

    bsd_close(transport_state->file_descriptor);
}
