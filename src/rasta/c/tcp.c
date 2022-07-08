#include <stdio.h>
#include <string.h> //memset
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
// TODO: move RastaState/RastaConnectionState
#include "tcp.h"
#include "rmemory.h"
#include "bsd_utils.h"
#include <stdbool.h>

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "ssl_utils.h"
#endif

void tcp_init(struct RastaState *state, const struct RastaConfigTLS *tls_config)
{
    state->tls_config = tls_config;
    state->file_descriptor = bsd_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

#ifdef ENABLE_TLS

static bool is_tls_server(const struct RastaConfigTLS *tls_config)
{
    // client has CA cert but no server certs
    return tls_config->cert_path[0] && tls_config->key_path[0];
}
#endif

static void handle_tls_mode(struct RastaState *state)
{
    const struct RastaConfigTLS *tls_config = state->tls_config;
    switch (tls_config->mode)
    {
    case TLS_MODE_DISABLED:
        state->activeMode = TLS_MODE_DISABLED;
        break;
#ifdef ENABLE_TLS
    case TLS_MODE_TLS_1_3:
        state->activeMode = TLS_MODE_TLS_1_3;
        if (is_tls_server(tls_config))
        {
            wolfssl_start_tls_server(state, tls_config);
        }
        else
        {
            wolfssl_start_tls_client(state, tls_config);
        }
        break;
#endif
    default:
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        exit(1);
    }
}

void tcp_bind(struct RastaState *state, uint16_t port)
{
    bsd_bind_port(state->file_descriptor, port);
    handle_tls_mode(state);
}

void tcp_bind_device(struct RastaState *state, uint16_t port, char *ip)
{
    bsd_bind_device(state->file_descriptor, port, ip);
    handle_tls_mode(state);
}

void tcp_listen(struct RastaState *state)
{
    if (listen(state->file_descriptor, MAX_PENDING_CONNECTIONS) < 0)
    {
        // listen failed
        perror("error whe listening to file_descriptor " + state->file_descriptor);
        exit(1);
    }
}

void tcp_accept(struct RastaState *state, struct RastaConnectionState *connectionState)
{
    struct sockaddr_in empty_sockaddr_in;
    socklen_t sender_len = sizeof(empty_sockaddr_in);
    int socket;
    if ((socket = accept(state->file_descriptor, (struct sockaddr *)&empty_sockaddr_in, &sender_len)) < 0)
    {
        perror("tcp failed to accept connection");
        exit(1);
    }

#ifdef ENABLE_TLS
    /* Create a WOLFSSL object */
    if ((connectionState->ssl = wolfSSL_new(state->ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        exit(1);
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(connectionState->ssl, socket);
    connectionState->tls_state = RASTA_TLS_CONNECTION_READY;

    /* Establish TLS connection */
    int ret = wolfSSL_accept(connectionState->ssl);
    if (ret != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "wolfSSL_accept error = %d\n",
                wolfSSL_get_error(connectionState->ssl, ret));
        exit(1);
    }
#endif

    connectionState->file_descriptor = socket;
}

void tcp_connect(struct RastaState *state, char *host, uint16_t port)
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

    if (connect(state->file_descriptor, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("tcp connection failed");
        exit(1);
    }

#ifdef ENABLE_TLS
    state->ssl = wolfSSL_new(state->ctx);
    if (!state->ssl)
    {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(state->ssl, 0));
        fprintf(stderr, "Error allocating WolfSSL session: %s.\n", error_str);
        exit(1);
    }

    if (state->tls_config->tls_hostname[0])
    {
        wolfSSL_check_domain_name(state->ssl, state->tls_config->tls_hostname);
    }
    else
    {
        fprintf(stderr, "No TLS hostname specified. Will accept ANY valid TLS certificate. Double-check configuration file.");
    }
    /* Attach wolfSSL to the socket */
    if (wolfSSL_set_fd(state->ssl, state->file_descriptor) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        exit(1);
    }

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(state->ssl) != WOLFSSL_SUCCESS)
    {
        // int readErr = wolfSSL_get_error(state->ssl, 0);
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        exit(1);
    }
#endif
}
#ifdef ENABLE_TLS
size_t tcp_receive(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
{
    (void)sender;
    return wolfssl_receive_tls(ssl, received_message, max_buffer_len);
}
#else
size_t tcp_receive(struct RastaState *state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
{
    if (state->activeMode == TLS_MODE_DISABLED)
    {
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(state->file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *)sender, &sender_len)) < 0)
        {
            perror("an error occured while trying to receive data");
            exit(1);
        }

        return (size_t)recv_len;
    }
    return 0;
}
#endif
#ifdef ENABLE_TLS
void tcp_send(WOLFSSL *ssl, unsigned char *message, size_t message_len)
{
    wolfssl_send_tls(ssl, message, message_len);
}
#else
void tcp_send(struct RastaState *state, unsigned char *message, size_t message_len, char *host, uint16_t port)
{
    bsd_send(state->file_descriptor, message, message_len, host, port);
}
#endif

void tcp_close(struct RastaState *state)
{
#ifdef ENABLE_TLS
    if (state->activeMode != TLS_MODE_DISABLED)
    {
        wolfssl_cleanup(state);
    }
#endif

    bsd_close(state->file_descriptor);
}
