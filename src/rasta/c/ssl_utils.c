#include "ssl_utils.h"
#include <stdbool.h>
#include <wolfssl/error-ssl.h>

#ifdef ENABLE_TLS

// #define DEBUG_WOLFSSL
void wolfssl_initialize_if_necessary()
{
    static bool wolfssl_initialized = false;
    if (!wolfssl_initialized)
    {
        wolfssl_initialized = true;
        wolfSSL_Init();
    }
}

void wolfssl_start_dtls_server(struct RastaState *state, const struct RastaConfigTLS *tls_config)
{
    wolfssl_start_server(state, tls_config, wolfDTLSv1_2_server_method());

    // TODO: remove duplicated code in tcp_accept
    state->ssl = wolfSSL_new(state->ctx);
    if (!state->ssl)
    {
        fprintf(stderr, "Error allocating WolfSSL object.\n");
        exit(1);
    }
    wolfSSL_set_fd(state->ssl, state->file_descriptor);

    // wolfSSL_set_fd(state->ssl, state->file_descriptor);
    state->tls_state = RASTA_TLS_CONNECTION_READY;
}

void wolfssl_start_tls_server(struct RastaState *state, const struct RastaConfigTLS *tls_config)
{
    wolfssl_start_server(state, tls_config, wolfTLSv1_3_server_method());
}

void wolfssl_start_server(struct RastaState *state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *server_method)
{
    int err;
    wolfssl_initialize_if_necessary();
    state->ctx = wolfSSL_CTX_new(server_method);
    if (!state->ctx)
    {
        fprintf(stderr, "Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if (!tls_config->ca_cert_path[0] || !tls_config->cert_path[0] || !tls_config->key_path[0])
    {
        fprintf(stderr, "CA certificate path, server certificate path or server private key path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(state->ctx, tls_config->ca_cert_path, 0) !=
        SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading CA certificate file %s.\n", tls_config->ca_cert_path);
        exit(1);
    }
    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(state->ctx, tls_config->cert_path, SSL_FILETYPE_PEM) !=
        SSL_SUCCESS)
    {
        printf("Error loading server certificate file %s as PEM file.\n", tls_config->cert_path);
        exit(1);
    }
    /* Load server Keys */
    if ((err = wolfSSL_CTX_use_PrivateKey_file(state->ctx, tls_config->key_path,
                                               SSL_FILETYPE_PEM)) != SSL_SUCCESS)
    {
        printf("Error loading server private key file %s as PEM file: %d.\n", tls_config->key_path, err);
        exit(1);
    }
    state->tls_config = tls_config;
}

void set_dtls_async(struct RastaState *state)
{
    set_socket_async(state, wolfSSL_dtls_set_using_nonblock);
}

void set_tls_async(int fd, WOLFSSL *ssl)
{
    int socket_flags;
    // set socket to non-blocking so we can select() on it
    socket_flags = fcntl(fd, F_GETFL, 0);
    if (socket_flags < 0)
    {
        perror("Error getting socket flags");
        exit(1);
    }
    socket_flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, socket_flags) != 0)
    {
        perror("Error setting socket non-blocking");
        exit(1);
    }

    // inform wolfssl to expect read / write errors due to non-blocking nature of socket
    wolfSSL_set_using_nonblock(ssl, 1);
}

void set_socket_async(struct RastaState *state, WOLFSSL_ASYNC_METHOD *wolfssl_async_method)
{
    int socket_flags;
    // set socket to non-blocking so we can select() on it
    socket_flags = fcntl(state->file_descriptor, F_GETFL, 0);
    if (socket_flags < 0)
    {
        perror("Error getting socket flags");
        exit(1);
    }
    socket_flags |= O_NONBLOCK;
    if (fcntl(state->file_descriptor, F_SETFL, socket_flags) != 0)
    {
        perror("Error setting socket non-blocking");
        exit(1);
    }

    // inform wolfssl to expect read / write errors due to non-blocking nature of socket
    (*wolfssl_async_method)(state->ssl, 1);
}

void wolfssl_start_dtls_client(struct RastaState *state, const struct RastaConfigTLS *tls_config)
{
    wolfssl_start_client(state, tls_config, wolfDTLSv1_2_client_method());
}

void wolfssl_start_tls_client(struct RastaState *state, const struct RastaConfigTLS *tls_config)
{
    wolfssl_start_client(state, tls_config, wolfTLSv1_3_client_method());
}

void wolfssl_start_client(struct RastaState *state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *client_method)
{
    wolfssl_initialize_if_necessary();
    state->ctx = wolfSSL_CTX_new(client_method);
    if (!state->ctx)
    {
        fprintf(stderr, "Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if (!tls_config->ca_cert_path[0])
    {
        fprintf(stderr, "CA certificate path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(state->ctx, tls_config->ca_cert_path, 0) !=
        SSL_SUCCESS)
    {

        fprintf(stderr, "Error loading CA certificate file %s\n", tls_config->ca_cert_path);
        exit(1);
    }

    if (tls_config->cert_path[0] && tls_config->key_path[0]) {
        /* Load client certificates */
        if (wolfSSL_CTX_use_certificate_file(state->ctx, tls_config->cert_path, SSL_FILETYPE_PEM) !=
            SSL_SUCCESS)
        {
            printf("Error loading client certificate file %s as PEM file.\n", tls_config->cert_path);
            exit(1);
        }
        /* Load client Keys */
        int err;
        if ((err = wolfSSL_CTX_use_PrivateKey_file(state->ctx, tls_config->key_path,
                                                SSL_FILETYPE_PEM)) != SSL_SUCCESS)
        {
            printf("Error loading client private key file %s as PEM file: %d.\n", tls_config->key_path, err);
            exit(1);
        }
    }

#ifdef USE_UDP
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

    wolfSSL_set_fd(state->ssl, state->file_descriptor);
    state->tls_state = RASTA_TLS_CONNECTION_READY;
#endif
}

void wolfssl_send(WOLFSSL *ssl, unsigned char *message, size_t message_len)
{
    if (wolfSSL_write(ssl, message, (int)message_len) != (int)message_len)
    {
        fprintf(stderr, "WolfSSL write error!");
        exit(1);
    }
}

void wolfssl_send_dtls(struct RastaState *state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver)
{
    if (state->tls_state != RASTA_TLS_CONNECTION_ESTABLISHED)
    {
        wolfSSL_dtls_set_peer(state->ssl, receiver, sizeof(*receiver));

        if (wolfSSL_connect(state->ssl) != SSL_SUCCESS)
        {
            int connect_error = wolfSSL_get_error(state->ssl, 0);
            fprintf(stderr, "WolfSSL connect error: %s\n", wolfSSL_ERR_reason_error_string(connect_error));
            exit(1);
        }
        state->tls_state = RASTA_TLS_CONNECTION_ESTABLISHED;
        set_socket_async(state, wolfSSL_dtls_set_using_nonblock);
    }

    wolfssl_send(state->ssl, message, message_len);
}

void wolfssl_send_tls(WOLFSSL *ssl, unsigned char *message, size_t message_len)
{
    wolfssl_send(ssl, message, message_len);
}

ssize_t wolfssl_receive_tls(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len)
{
    int receive_len, received_total = 0;

    // read as many bytes as available at this time
    do
    {
        receive_len = wolfSSL_read(ssl, received_message, (int)max_buffer_len);
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
        int readErr = wolfSSL_get_error(ssl, 0);
        if (readErr == SOCKET_PEER_CLOSED_E) {
            return -1;
        }
        else if (readErr != SSL_ERROR_WANT_READ && readErr != SSL_ERROR_WANT_WRITE)
        {
            fprintf(stderr, "WolfSSL decryption failed: %s.\n", wolfSSL_ERR_reason_error_string(readErr));
            exit(1);
        }
    }

    return received_total;
}

void wolfssl_cleanup(struct RastaState *state)
{
    state->tls_state = RASTA_TLS_CONNECTION_CLOSED;
    wolfSSL_set_fd(state->ssl, 0);
    wolfSSL_shutdown(state->ssl);
    wolfSSL_free(state->ssl);
    wolfSSL_CTX_free(state->ctx);
}

#endif
