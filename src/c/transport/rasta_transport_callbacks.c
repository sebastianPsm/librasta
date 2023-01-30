#include "rasta_transport_callbacks.h"

#ifdef USE_TCP

#ifdef ENABLE_TLS
void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    UNUSED(mux);
    UNUSED(channel_index);
    tls_send(channel->ssl, data_to_send.bytes, data_to_send.length);
}

int receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    UNUSED(mux);
    return tls_receive(data->ssl, buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data) {
    channel->fd = data->event->fd;
    channel->ssl = data->ssl;
}

#else
void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    UNUSED(channel_index);
    tcp_send(&mux->transport_states[channel_index], data_to_send.bytes, data_to_send.length, channel->ip_address, channel->port);
}

int receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    return tcp_receive(&mux->transport_states[data->channel_index], buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data) {
    channel->fd = data->event->fd;
}
#endif
#endif

#ifdef USE_UDP
void send_callback(redundancy_mux *mux, struct RastaByteArray data_to_send, rasta_transport_channel *channel, unsigned int channel_index) {
    udp_send(&mux->transport_states[channel_index], data_to_send.bytes, data_to_send.length, channel->ip_address, channel->port);
}

int receive_callback(redundancy_mux *mux, struct receive_event_data *data, unsigned char *buffer, struct sockaddr_in *sender) {
    return udp_receive(&mux->transport_states[data->channel_index], buffer, MAX_DEFER_QUEUE_MSG_SIZE, sender);
}

// UDP doesn't need the extension function, as it is the default behavior.
// This callback just fits the signatur of update_redundancy_channels.
void redundancy_channel_extension_callback(rasta_transport_channel *channel, struct receive_event_data *data) {
    (void)channel;
    (void)data;
}
#endif
