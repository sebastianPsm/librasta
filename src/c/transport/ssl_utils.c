#include <rasta/ssl_utils.h>

#include <stdbool.h>
#include <wolfssl/error-ssl.h>

#ifdef ENABLE_TLS

// #define DEBUG_WOLFSSL
void wolfssl_initialize_if_necessary() {
    static bool wolfssl_initialized = false;
    if (!wolfssl_initialized) {
        wolfssl_initialized = true;
        wolfSSL_Init();
    }
}

void wolfssl_start_dtls_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
    wolfssl_start_server(transport_state, tls_config, wolfDTLSv1_2_server_method());

    // TODO: remove duplicated code in tcp_accept
    transport_state->ssl = wolfSSL_new(transport_state->ctx);
    if (!transport_state->ssl) {
        fprintf(stderr, "Error allocating WolfSSL object.\n");
        exit(1);
    }
    wolfSSL_set_fd(transport_state->ssl, transport_state->file_descriptor);

    // wolfSSL_set_fd(transport_state->ssl, transport_state->file_descriptor);
    transport_state->tls_state = RASTA_TLS_CONNECTION_READY;
}

void wolfssl_start_tls_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
    wolfssl_start_server(transport_state, tls_config, wolfTLSv1_3_server_method());
}

void wolfssl_start_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *server_method) {
    int err;
    wolfssl_initialize_if_necessary();
    transport_state->ctx = wolfSSL_CTX_new(server_method);
    if (!transport_state->ctx) {
        fprintf(stderr, "Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if (!tls_config->ca_cert_path[0] || !tls_config->cert_path[0] || !tls_config->key_path[0]) {
        fprintf(stderr, "CA certificate path, server certificate path or server private key path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(transport_state->ctx, tls_config->ca_cert_path, 0) !=
        SSL_SUCCESS) {
        fprintf(stderr, "Error loading CA certificate file %s.\n", tls_config->ca_cert_path);
        exit(1);
    }
    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(transport_state->ctx, tls_config->cert_path, SSL_FILETYPE_PEM) !=
        SSL_SUCCESS) {
        printf("Error loading server certificate file %s as PEM file.\n", tls_config->cert_path);
        exit(1);
    }
    /* Load server Keys */
    if ((err = wolfSSL_CTX_use_PrivateKey_file(transport_state->ctx, tls_config->key_path,
                                               SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        printf("Error loading server private key file %s as PEM file: %d.\n", tls_config->key_path, err);
        exit(1);
    }
    transport_state->tls_config = tls_config;
}

void set_dtls_async(struct rasta_transport_state *transport_state) {
    set_socket_async(transport_state, wolfSSL_dtls_set_using_nonblock);
}

void set_tls_async(int fd, WOLFSSL *ssl) {
    int socket_flags;
    // set socket to non-blocking so we can select() on it
    socket_flags = fcntl(fd, F_GETFL, 0);
    if (socket_flags < 0) {
        perror("Error getting socket flags");
        exit(1);
    }
    socket_flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, socket_flags) != 0) {
        perror("Error setting socket non-blocking");
        exit(1);
    }

    // inform wolfssl to expect read / write errors due to non-blocking nature of socket
    wolfSSL_set_using_nonblock(ssl, 1);
}

void set_socket_async(struct rasta_transport_state *transport_state, WOLFSSL_ASYNC_METHOD *wolfssl_async_method) {
    int socket_flags;
    // set socket to non-blocking so we can select() on it
    socket_flags = fcntl(transport_state->file_descriptor, F_GETFL, 0);
    if (socket_flags < 0) {
        perror("Error getting socket flags");
        exit(1);
    }
    socket_flags |= O_NONBLOCK;
    if (fcntl(transport_state->file_descriptor, F_SETFL, socket_flags) != 0) {
        perror("Error setting socket non-blocking");
        exit(1);
    }

    // inform wolfssl to expect read / write errors due to non-blocking nature of socket
    (*wolfssl_async_method)(transport_state->ssl, 1);
}

void wolfssl_start_dtls_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
    wolfssl_start_client(transport_state, tls_config, wolfDTLSv1_2_client_method());
}

void wolfssl_start_tls_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
    wolfssl_start_client(transport_state, tls_config, wolfTLSv1_3_client_method());
}

void wolfssl_start_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *client_method) {
    wolfssl_initialize_if_necessary();
    transport_state->ctx = wolfSSL_CTX_new(client_method);
    if (!transport_state->ctx) {
        fprintf(stderr, "Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if (!tls_config->ca_cert_path[0]) {
        fprintf(stderr, "CA certificate path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(transport_state->ctx, tls_config->ca_cert_path, 0) !=
        SSL_SUCCESS) {

        fprintf(stderr, "Error loading CA certificate file %s\n", tls_config->ca_cert_path);
        exit(1);
    }

    if (tls_config->cert_path[0] && tls_config->key_path[0]) {
        /* Load client certificates */
        if (wolfSSL_CTX_use_certificate_file(transport_state->ctx, tls_config->cert_path, SSL_FILETYPE_PEM) !=
            SSL_SUCCESS) {
            printf("Error loading client certificate file %s as PEM file.\n", tls_config->cert_path);
            exit(1);
        }
        /* Load client Keys */
        int err;
        if ((err = wolfSSL_CTX_use_PrivateKey_file(transport_state->ctx, tls_config->key_path,
                                                   SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            fprintf(stderr, "Error loading client private key file %s as PEM file: %d.\n", tls_config->key_path, err);
            exit(1);
        }
    }

#ifdef USE_UDP
    transport_state->ssl = wolfSSL_new(transport_state->ctx);
    if (!transport_state->ssl) {
        const char *error_str = wolfSSL_ERR_reason_error_string(wolfSSL_get_error(transport_state->ssl, 0));
        fprintf(stderr, "Error allocating WolfSSL session: %s.\n", error_str);
        exit(1);
    }

    if (transport_state->tls_config->tls_hostname[0]) {
        const int ret = wolfSSL_check_domain_name(transport_state->ssl, transport_state->tls_config->tls_hostname);
        if (ret != SSL_SUCCESS) {
            fprintf(stderr, "Could not add domain name check for domain %s: %d", transport_state->tls_config->tls_hostname, ret);
            exit(1);
        }
    } else {
        fprintf(stderr, "No TLS hostname specified. Will accept ANY valid TLS certificate. Double-check configuration file.\n");
    }

    wolfSSL_set_fd(transport_state->ssl, transport_state->file_descriptor);
    transport_state->tls_state = RASTA_TLS_CONNECTION_READY;
#endif
}

void wolfssl_send(WOLFSSL *ssl, unsigned char *message, size_t message_len) {
    if (wolfSSL_write(ssl, message, (int)message_len) != (int)message_len) {
        fprintf(stderr, "WolfSSL write error!");
        exit(1);
    }
}

void wolfssl_send_dtls(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver) {
    if (transport_state->tls_state != RASTA_TLS_CONNECTION_ESTABLISHED) {
        wolfSSL_dtls_set_peer(transport_state->ssl, receiver, sizeof(*receiver));

        if (wolfSSL_connect(transport_state->ssl) != SSL_SUCCESS) {
            int connect_error = wolfSSL_get_error(transport_state->ssl, 0);
            fprintf(stderr, "WolfSSL connect error: %s\n", wolfSSL_ERR_reason_error_string(connect_error));
            exit(1);
        }

        tls_pin_certificate(transport_state->ssl, transport_state->tls_config->peer_tls_cert_path);

        transport_state->tls_state = RASTA_TLS_CONNECTION_ESTABLISHED;
        set_socket_async(transport_state, wolfSSL_dtls_set_using_nonblock);
    }

    wolfssl_send(transport_state->ssl, message, message_len);
}

void wolfssl_send_tls(WOLFSSL *ssl, unsigned char *message, size_t message_len) {
    wolfssl_send(ssl, message, message_len);
}

ssize_t wolfssl_receive_tls(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len) {
    int receive_len, received_total = 0;

    // read as many bytes as available at this time
    do {
        receive_len = wolfSSL_read(ssl, received_message, (int)max_buffer_len);
        if (receive_len < 0) {
            break;
        }
        received_message += receive_len;
        max_buffer_len -= receive_len;
        received_total += receive_len;
    } while (receive_len > 0 && max_buffer_len);

    if (receive_len < 0) {
        int readErr = wolfSSL_get_error(ssl, 0);
        if (readErr == SOCKET_PEER_CLOSED_E) {
            return -1;
        } else if (readErr != SSL_ERROR_WANT_READ && readErr != SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "WolfSSL decryption failed: %s.\n", wolfSSL_ERR_reason_error_string(readErr));
            exit(1);
        }
    }

    return received_total;
}

void wolfssl_cleanup(struct rasta_transport_state *transport_state) {
    transport_state->tls_state = RASTA_TLS_CONNECTION_CLOSED;
    wolfSSL_set_fd(transport_state->ssl, 0);
    wolfSSL_shutdown(transport_state->ssl);
    wolfSSL_free(transport_state->ssl);
    wolfSSL_CTX_free(transport_state->ctx);
}

#define CHECK_NULL_AND_ASSIGN(type, varname, invocation) \
    type *varname = invocation;                          \
    if (!(varname)) {                                    \
        fprintf(stderr, #invocation " failed!\n");       \
        exit(1);                                         \
    }
#define SHA256_BUFFER_LENGTH_BYTES 64

void generate_certificate_digest(WOLFSSL_X509 *peer_cert,
                                 unsigned char *peer_digest_buffer,
                                 unsigned int *peer_digest_buffer_size) {
    int ret;
    int der_length;
    CHECK_NULL_AND_ASSIGN(const unsigned char, der_buffer, wolfSSL_X509_get_der(peer_cert, &der_length));

    ret = wolfSSL_X509_digest(peer_cert, wolfSSL_EVP_sha256(), peer_digest_buffer, peer_digest_buffer_size);

    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "Could not generate peer certificate sha256 digest!\n");
        exit(1);
    }
}

void tls_pin_certificate(WOLFSSL *ssl, const char *peer_tls_cert_path) {
    if (peer_tls_cert_path[0]) {
        // public key pinning: check TLS public key of peer
        unsigned char peer_digest_buffer[SHA256_BUFFER_LENGTH_BYTES], pinned_digest_buffer[SHA256_BUFFER_LENGTH_BYTES];
        unsigned int peer_digest_buffer_size, pinned_digest_buffer_size;
        CHECK_NULL_AND_ASSIGN(WOLFSSL_X509, peer_cert, wolfSSL_get_peer_certificate(ssl));
        CHECK_NULL_AND_ASSIGN(WOLFSSL_X509, pinned_cert, wolfSSL_X509_load_certificate_file(peer_tls_cert_path, SSL_FILETYPE_PEM));
        generate_certificate_digest(peer_cert, peer_digest_buffer, &peer_digest_buffer_size);
        generate_certificate_digest(pinned_cert, pinned_digest_buffer, &pinned_digest_buffer_size);
        if (peer_digest_buffer_size != pinned_digest_buffer_size) {
            fprintf(stderr, "Internal error - certificate digests do not have the same length\n (%d vs. %d bytes)!", peer_digest_buffer_size, pinned_digest_buffer_size);
            exit(1);
        }
        if (memcmp(peer_digest_buffer, pinned_digest_buffer, pinned_digest_buffer_size) != 0) {
            struct logger_t sha_logger = logger_init(LOG_LEVEL_DEBUG, LOGGER_TYPE_CONSOLE);
            fprintf(stderr, "Certificate Pinning error - peer certificate hash does not match!\n");
            logger_hexdump(&sha_logger, LOG_LEVEL_DEBUG, peer_digest_buffer, peer_digest_buffer_size, "Peer certificate (digest)");
            logger_hexdump(&sha_logger, LOG_LEVEL_DEBUG, pinned_digest_buffer, pinned_digest_buffer_size, "Pinned certificate (digest)");
            exit(1);
        }
    }
}

#endif
