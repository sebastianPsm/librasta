
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

#ifdef ENABLE_TLS
#include <rasta/ssl_utils.h>
#endif

#define MAX_WARNING_LENGTH_BYTES 128

static void handle_port_unavailable(const uint16_t port) {
    const char *warning_format = "could not bind the socket to port %d";
    char warning_mbuf[MAX_WARNING_LENGTH_BYTES + 1];
    snprintf(warning_mbuf, MAX_WARNING_LENGTH_BYTES, warning_format, port);

    // bind failed
    perror("warning_mbuf");
    exit(1);
}

#ifdef ENABLE_TLS

#ifdef ENABLE_UDP
static void
get_client_addr_from_socket(const struct RastaState *transport_state, struct sockaddr_in *client_addr, socklen_t *addr_len) {
    ssize_t received_bytes;
    char buffer;
    // wait for the first byte of the DTLS Client hello to identify the prospective client
    received_bytes = recvfrom(transport_state->file_descriptor, &buffer, sizeof(buffer), MSG_PEEK,
                              (struct sockaddr *)client_addr, addr_len);

    if (received_bytes < 0) {
        perror("No clients waiting to connect");
        exit(1);
    }
}
#endif

#ifdef ENABLE_UDP
static void wolfssl_accept(struct RastaState *transport_state) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // need to open UDP "connection" and accept client before the remaining methods (send / receive) work as expected by RaSTA

    get_client_addr_from_socket(transport_state, &client_addr, &addr_len);
    // we have received a client hello and can now accept the connection

    if (connect(transport_state->file_descriptor, (struct sockaddr *)&client_addr, sizeof(client_addr)) != 0) {
        perror("Could not connect to client");
        exit(1);
    }

    if (wolfSSL_accept(transport_state->ssl) != SSL_SUCCESS) {

        int e = wolfSSL_get_error(transport_state->ssl, 0);

        fprintf(stderr, "WolfSSL could not accept connection: %s\n", wolfSSL_ERR_reason_error_string(e));
        exit(1);
    }

    tls_pin_certificate(transport_state->ssl, transport_state->tls_config->peer_tls_cert_path);

    set_dtls_async(transport_state);
}
#endif

static size_t wolfssl_receive_dtls(struct rasta_transport_state *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    int receive_len, received_total = 0;
#ifdef ENABLE_UDP
    socklen_t sender_size = sizeof(*sender);

    get_client_addr_from_socket(transport_state, sender, &sender_size);

    if (transport_state->tls_state == RASTA_TLS_CONNECTION_READY) {
        wolfssl_accept(transport_state);
        transport_state->tls_state = RASTA_TLS_CONNECTION_ESTABLISHED;
        return 0;
    }
    if (transport_state->tls_state == RASTA_TLS_CONNECTION_ESTABLISHED) {
        // read as many bytes as available at this time
        do {
            receive_len = wolfSSL_read(transport_state->ssl, received_message, (int)max_buffer_len);
            if (receive_len < 0) {
                break;
            }
            received_message += receive_len;
            max_buffer_len -= receive_len;
            received_total += receive_len;
        } while (receive_len > 0 && max_buffer_len);

        if (receive_len < 0) {
            int readErr = wolfSSL_get_error(transport_state->ssl, 0);
            if (readErr != SSL_ERROR_WANT_READ && readErr != SSL_ERROR_WANT_WRITE) {
                fprintf(stderr, "WolfSSL decryption failed: %s.\n", wolfSSL_ERR_reason_error_string(readErr));
                exit(1);
            }
        }
    }
#else
    (void)(receive_len);
    (void)(transport_state);
    (void)(received_message);
    (void)(max_buffer_len);
    (void)(sender);
#endif
    return received_total;
}

static bool is_dtls_server(const struct RastaConfigTLS *tls_config) {
    // client has CA cert but no server certs
    return tls_config->cert_path[0] && tls_config->key_path[0];
}

#endif

static void handle_tls_mode(struct rasta_transport_state *transport_state) {
    const struct RastaConfigTLS *tls_config = transport_state->tls_config;
    switch (tls_config->mode) {
    case TLS_MODE_DISABLED: {
        transport_state->activeMode = TLS_MODE_DISABLED;
        break;
    }
    case TLS_MODE_DTLS_1_2: {
        transport_state->activeMode = TLS_MODE_DTLS_1_2;
#ifdef ENABLE_TLS
        if (is_dtls_server(tls_config)) {
            wolfssl_start_dtls_server(transport_state, tls_config);
        } else {
            wolfssl_start_dtls_client(transport_state, tls_config);
        }
#else
        printf("TLS is not enabled but rasta config transport_state is TLS_MODE_DTLS_1_2\n");
        exit(1);
#endif
        break;
    }
    default: {
        fprintf(stderr, "Unknown or unsupported TLS mode: %u", tls_config->mode);
        exit(1);
    }
    }
}

void udp_bind(struct rasta_transport_state *transport_state, uint16_t port) {
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

void udp_bind_device(struct rasta_transport_state *transport_state, uint16_t port, char *ip) {
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

void udp_close(struct rasta_transport_state *transport_state) {
    int file_descriptor = transport_state->file_descriptor;
    if (file_descriptor >= 0) {

#ifdef ENABLE_TLS
        if (transport_state->activeMode != TLS_MODE_DISABLED) {
            wolfssl_cleanup(transport_state);
        }
#endif

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

size_t udp_receive(struct rasta_transport_state *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
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
#ifdef ENABLE_TLS
    else {
        return wolfssl_receive_dtls(transport_state, received_message, max_buffer_len, sender);
    }
#endif
    return 0;
}

void udp_send(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, char *host, uint16_t port) {
    struct sockaddr_in receiver = host_port_to_sockaddr(host, port);
    if (transport_state->activeMode == TLS_MODE_DISABLED) {

        // send the message using the other send function
        udp_send_sockaddr(transport_state, message, message_len, receiver);
    }
#ifdef ENABLE_TLS
    else {
        wolfssl_send_dtls(transport_state, message, message_len, &receiver);
    }
#endif
}

void udp_send_sockaddr(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, struct sockaddr_in receiver) {
    if (transport_state->activeMode == TLS_MODE_DISABLED) {
        if (sendto(transport_state->file_descriptor, message, message_len, 0, (struct sockaddr *)&receiver, sizeof(receiver)) ==
            -1) {
            perror("failed to send data");
            exit(1);
        }
    }
#ifdef ENABLE_TLS
    else {
        const struct RastaConfigTLS *tls_config = transport_state->tls_config;
        transport_state->tls_config = tls_config;
        wolfssl_send_dtls(transport_state, message, message_len, &receiver);
    }
#endif
}

void udp_init(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config) {
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
