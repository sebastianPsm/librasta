#pragma once
#ifndef TYPES_H
#define TYPES_H
#include "types.h"
#endif

typedef void(WOLFSSL_ASYNC_METHOD)(WOLFSSL *, int);
typedef int(WOLFSSL_SET_PEER_METHOD)(WOLFSSL *, void *, unsigned int);

void wolfssl_initialize_if_necessary();

void wolfssl_start_dtls_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_tls_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_server(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *server_method);

void set_dtls_async(struct rasta_transport_state *transport_state);

void set_tls_async(int fd, WOLFSSL *ssl);

void set_socket_async(struct rasta_transport_state *transport_state, WOLFSSL_ASYNC_METHOD *wolfssl_async_method);

void wolfssl_start_dtls_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_tls_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config);

void wolfssl_start_client(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config, WOLFSSL_METHOD *client_method);

void wolfssl_send(WOLFSSL *ssl, unsigned char *message, size_t message_len);

void wolfssl_send_tls(WOLFSSL *ssl, unsigned char *message, size_t message_len);

void wolfssl_send_dtls(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver);

ssize_t wolfssl_receive_tls(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len);

void wolfssl_cleanup(struct rasta_transport_state *transport_state);

void tls_pin_certificate(WOLFSSL *ssl, const char *peer_tls_cert_path);
