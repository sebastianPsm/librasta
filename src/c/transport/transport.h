#pragma once

#include <rasta/rasta_red_multiplexer.h>
#include <rasta/transport.h>

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index);
ssize_t receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender);
void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data);

void transport_initialize(rasta_transport_channel *channel, struct rasta_transport_state transport_state, char *ip, uint16_t port);
void transport_connect(redundancy_mux *mux, unsigned int channel, char *host, uint16_t port);
void transport_reconnect(redundancy_mux *mux, unsigned int channel);
void transport_close(rasta_transport_channel *channel);
