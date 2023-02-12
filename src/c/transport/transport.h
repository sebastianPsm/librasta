#pragma once

#include <arpa/inet.h>
#include <rasta/rasta_red_multiplexer.h>

#include "diagnostics.h"
#include "events.h"

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

enum rasta_tls_connection_state {
    RASTA_TLS_CONNECTION_READY,
    RASTA_TLS_CONNECTION_ESTABLISHED,
    RASTA_TLS_CONNECTION_CLOSED
};
#endif

/**
 * representation of a RaSTA redundancy layer transport channel
 */
typedef struct rasta_transport_channel {

    int id;

    bool connected;

    fd_event receive_event;

    struct receive_event_data receive_event_data;

    /**
     * IPv4 address in format a.b.c.d
     */
    char *remote_ip_address;

    enum RastaTLSMode tls_mode;

#ifdef USE_TCP
    /**
     * filedescriptor
     * */
    int fd;
#ifdef ENABLE_TLS
    WOLFSSL *ssl;
#endif
#endif

    /**
     * port number
     */
    uint16_t remote_port;

    /**
     * data used for transport channel diagnostics as in 6.6.3.2
     */
    rasta_redundancy_diagnostics_data diagnostics_data;

    void (*send_callback)(redundancy_mux *mux, struct RastaByteArray data_to_send, struct rasta_transport_channel *channel, unsigned int channel_index);
} rasta_transport_channel;

typedef struct rasta_transport_socket {

    int id;

    int file_descriptor;

    enum RastaTLSMode activeMode;

    const struct RastaConfigTLS *tls_config;

#ifdef ENABLE_TLS

    WOLFSSL_CTX *ctx;

    WOLFSSL *ssl;

    enum rasta_tls_connection_state state;
#endif

} rasta_transport_socket;

typedef struct rasta_transport_connection {
    rasta_transport_channel fixme;
} rasta_transport_connection;

#ifdef ENABLE_TLS
struct rasta_connected_transport_channel_state {
    const struct RastaConfigTLS *tls_config;
    enum RastaTLSMode activeMode;
    WOLFSSL_CTX *ctx;
    int file_descriptor;
    WOLFSSL *ssl;
    enum rasta_tls_connection_state state;
};
#endif

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index);
ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender);

void transport_create_socket(rasta_transport_socket *socket, int id, const struct RastaConfigTLS *tls_config);
void transport_bind(rasta_transport_socket *socket, const char *ip, uint16_t port);
// void transport_initialize(rasta_transport_channel *channel, rasta_transport_connection *transport_state, char *local_ip, uint16_t local_port, char *remote_ip, uint16_t remote_port, const struct RastaConfigTLS *tls_config);
void transport_listen(rasta_transport_socket *socket);
void transport_accept(rasta_transport_socket *socket, rasta_transport_channel* channel);
int transport_connect(rasta_transport_socket *socket, rasta_transport_channel *channel, char *host, uint16_t port);
int transport_redial(rasta_transport_channel* channel);
void transport_close(rasta_transport_channel *channel);
