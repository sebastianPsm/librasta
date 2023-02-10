#pragma once

#include <rasta/rasta_red_multiplexer.h>
#include <rasta/transport.h>

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index);
ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender);
void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data);

void transport_create_socket(rasta_transport_socket *socket, const struct RastaConfigTLS *tls_config);
void transport_bind(rasta_transport_socket *socket, const char *ip, uint16_t port);
// void transport_initialize(rasta_transport_channel *channel, rasta_transport_connection *transport_state, char *local_ip, uint16_t local_port, char *remote_ip, uint16_t remote_port, const struct RastaConfigTLS *tls_config);
void transport_listen(rasta_transport_socket *socket);
void transport_accept(rasta_transport_socket *socket, rasta_transport_channel* channel);
int transport_connect(rasta_transport_socket *socket, rasta_transport_channel *channel, char *host, uint16_t port);
int transport_redial(rasta_transport_channel* channel);
void transport_close(rasta_transport_channel *channel);
