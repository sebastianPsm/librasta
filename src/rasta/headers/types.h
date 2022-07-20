#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <config.h>

#ifdef ENABLE_TLS
enum RastaTLSConnectionState {
    RASTA_TLS_CONNECTION_READY,
    RASTA_TLS_CONNECTION_ESTABLISHED,
    RASTA_TLS_CONNECTION_CLOSED
};
#endif

struct RastaState
{
    int file_descriptor;
    enum RastaTLSMode activeMode;
    const struct RastaConfigTLS *tls_config;
#ifdef ENABLE_TLS
    WOLFSSL_CTX* ctx;

    WOLFSSL* ssl;
    enum RastaTLSConnectionState tls_state;

#endif
};

// #if defined(ENABLE_TLS) && defined(ENABLE_TCP)
#ifdef ENABLE_TLS
    struct RastaConnectionState
    {
        const struct RastaConfigTLS *tls_config;
        enum RastaTLSMode activeMode;
        WOLFSSL_CTX *ctx;
        int file_descriptor;
        WOLFSSL *ssl;
        enum RastaTLSConnectionState tls_state;
    };
#endif
