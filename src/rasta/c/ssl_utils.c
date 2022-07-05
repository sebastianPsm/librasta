#include "ssl_utils.h"
#include <stdbool.h>

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
    state->ssl = wolfSSL_new(state->ctx);
    if (!state->ssl)
    {
        fprintf(stderr, "Error allocating WolfSSL object.\n");
        exit(1);
    }

    wolfSSL_set_fd(state->ssl, state->file_descriptor);
    state->tls_state = RASTA_TLS_CONNECTION_READY;
    state->tls_config = tls_config;
}

void set_dtls_async(struct RastaState *state)
{
    set_socket_async(state, wolfSSL_dtls_set_using_nonblock);
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
}

void wolfssl_send_tls(struct RastaState *state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver)
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
        set_dtls_async(state);
    }

    if (wolfSSL_write(state->ssl, message, (int)message_len) != (int)message_len)
    {
        fprintf(stderr, "WolfSSL write error!");
        exit(1);
    }
}

void wolfssl_cleanup(struct RastaState *state)
{
    state->tls_state = RASTA_TLS_CONNECTION_CLOSED;
    wolfSSL_set_fd(state->ssl, 0);
    wolfSSL_shutdown(state->ssl);
    wolfSSL_free(state->ssl);
    wolfSSL_CTX_free(state->ctx);
}
