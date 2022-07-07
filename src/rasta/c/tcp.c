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
void get_client_addr_from_socket(const struct RastaState *state, struct sockaddr_in *client_addr, socklen_t *addr_len)
{
    ssize_t received_bytes;
    char buffer;
    // wait for the first byte of the DTLS Client hello to identify the prospective client
    received_bytes = recvfrom(state->file_descriptor, &buffer, sizeof(buffer), MSG_PEEK,
                              (struct sockaddr *)client_addr, addr_len);

    if (received_bytes < 0)
    {
        perror("No clients waiting to connect");
        exit(1);
    }
}

size_t wolfssl_receive_tls(struct RastaState *state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender)
{
    int receive_len, received_total = 0;
    socklen_t sender_size = sizeof(*sender);

    get_client_addr_from_socket(state, sender, &sender_size);

    if (state->tls_state == RASTA_TLS_CONNECTION_READY)
    {
        wolfSSL_accept(state->ssl);
        // wolfSSL_accept(state->file_descriptor);
        state->tls_state = RASTA_TLS_CONNECTION_ESTABLISHED;
        return 0;
    }
    if (state->tls_state == RASTA_TLS_CONNECTION_ESTABLISHED)
    {
        // read as many bytes as available at this time
        do
        {
            receive_len = wolfSSL_read(state->ssl, received_message, (int)max_buffer_len);
            if (receive_len < 0)
            {
                break;
            }
            received_message += receive_len;
            max_buffer_len -= receive_len;
            received_total += receive_len;
        } while (receive_len > 0 && max_buffer_len);

        if (receive_len < 0)
        {
            int readErr = wolfSSL_get_error(state->ssl, 0);
            if (readErr != SSL_ERROR_WANT_READ && readErr != SSL_ERROR_WANT_WRITE)
            {
                fprintf(stderr, "WolfSSL decryption failed: %s.\n", wolfSSL_ERR_reason_error_string(readErr));
                exit(1);
            }
        }
    }
    return received_total;
}

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
    if ((connectionState->ssl = wolfSSL_new(state->ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        exit(1);
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(connectionState->ssl, socket);

    if (wolfSSL_accept(connectionState->ssl) != SSL_SUCCESS)
    {

        int e = wolfSSL_get_error(connectionState->ssl, 0);

        fprintf(stderr, "WolfSSL could not accept connection: %s\n", wolfSSL_ERR_reason_error_string(e));
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
}

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

        return (size_t)recv_len; }
#ifdef ENABLE_TLS
    else
    {
        return wolfssl_receive_tls(state, received_message, max_buffer_len, sender);
    }
#endif
    return 0;
}

void tcp_send(struct RastaState *state, unsigned char *message, size_t message_len, char *host, uint16_t port)
{
    struct sockaddr_in receiver = host_port_to_sockaddr(host, port);
    if (state->activeMode == TLS_MODE_DISABLED)
    {
        bsd_send(state->file_descriptor, message, message_len, host, port); }
#ifdef ENABLE_TLS
#ifdef USE_TCP
    else
    {
        wolfssl_send_tls(state, message, message_len, &receiver);
    }
#endif
#endif
}

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
