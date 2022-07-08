#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "udp.h"

typedef void(WOLFSSL_ASYNC_METHOD)(WOLFSSL *, int);
typedef int(WOLFSSL_SET_PEER_METHOD)(WOLFSSL *, void *, unsigned int);

void wolfssl_initialize_if_necessary();

void wolfssl_start_dtls_server(struct RastaState *state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_tls_server(struct RastaState *state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_server(struct RastaState *state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *server_method);

void set_dtls_async(struct RastaState *state);

void set_socket_async(struct RastaState *state, WOLFSSL_ASYNC_METHOD *wolfssl_async_method);

void wolfssl_start_dtls_client(struct RastaState *state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_tls_client(struct RastaState *state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_client(struct RastaState *state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *client_method);

void wolfssl_send(WOLFSSL *ssl, unsigned char *message, size_t message_len);

void wolfssl_send_tls(WOLFSSL *ssl, unsigned char *message, size_t message_len);

void wolfssl_send_dtls(struct RastaState *state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver);

size_t wolfssl_receive_tls(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len);

void wolfssl_cleanup(struct RastaState *state);
