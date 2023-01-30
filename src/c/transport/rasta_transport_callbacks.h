#pragma once

#include <rasta/rasta_red_multiplexer.h>
#include <rasta/transport.h>

void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index);
int receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender);
void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data);
