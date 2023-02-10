#pragma once

#include <rasta/config.h>

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

enum rasta_tls_connection_state {
    RASTA_TLS_CONNECTION_READY,
    RASTA_TLS_CONNECTION_ESTABLISHED,
    RASTA_TLS_CONNECTION_CLOSED
};
#endif

typedef struct rasta_transport_connection {

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
