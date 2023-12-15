#include "rasta_redundancy_channel.h"
#include "../transport/transport.h"

int rasta_red_connect_transport_channel(rasta_redundancy_channel *channel, rasta_transport_socket *transport_socket) {
    rasta_transport_channel *transport_connection = &channel->transport_channels[transport_socket->id];
    transport_connect(transport_socket, transport_connection);
    return transport_connection->connected;
}

int redundancy_mux_connect_channel(redundancy_mux *mux, rasta_redundancy_channel *channel) {
    // add transport channels
    int success = 0;
    for (unsigned int i = 0; i < channel->transport_channel_count; i++) {
        channel->seq_rx = 0;
        channel->seq_tx = 0;
        // Provided transport channels have to match with local ports configured
        success |= rasta_red_connect_transport_channel(channel, &mux->transport_sockets[i]);
    }

    if (!success) {
        red_f_cleanup(channel);
        return 1;
    }

    logger_log(mux->logger, LOG_LEVEL_INFO, "RaSTA RedMux add channel", "added new redundancy channel for ID=0x%lX", channel->associated_id);

    return 0;
}

void redundancy_mux_close_channel(rasta_connection *conn, rasta_redundancy_channel *red_channel) {
    for (unsigned int i = 0; i < red_channel->transport_channel_count; ++i) {
        rasta_transport_channel *channel = &red_channel->transport_channels[i];
        logger_log(red_channel->mux->logger, LOG_LEVEL_DEBUG, "RaSTA RedMux remove channel", "closing transport channel %u/%u", i + 1, red_channel->transport_channel_count);
        transport_close_channel(channel);
        // if we are a TCP/TLS client (and transport_close_channel actually closes the channel), the socket fd also becomes invalid
        if (!channel->connected && conn->role == RASTA_ROLE_CLIENT) {
            channel->associated_socket->file_descriptor = -1;
        }
    }
}
