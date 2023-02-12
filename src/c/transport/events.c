#include "events.h"

#include <rasta/logging.h>
#include <rasta/rmemory.h>
#include <rasta/rastahandle.h>
#include "transport.h"
#include "diagnostics.h"

int channel_accept_event(void *carry_data) {
    struct accept_event_data *data = carry_data;

    logger_log(&data->h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux accept", "Socket ready to accept");

    rasta_transport_channel *channel = rmalloc(sizeof(rasta_transport_channel));
    transport_accept(data->socket, channel);
    channel->id = data->socket->id;

    // We cannot decide yet which redundancy_channel this transport_channel belongs to.
    // The communication partner has to send some data first.
    // For now, just register the receive event listener for the new connection.

    memset(&channel->receive_event, 0, sizeof(fd_event));
    channel->receive_event.enabled = 1;
    channel->receive_event.carry_data = &channel->receive_event_data;
    channel->receive_event.callback = channel_receive_event;
    channel->receive_event.fd = channel->fd;

    channel->receive_event_data.channel = channel;
    channel->receive_event_data.h = data->h;
#ifdef ENABLE_TLS
    channel->receive_event_data.ssl = data->socket->ssl;
#endif

    // TODO: channel might be leaked
    add_fd_event(data->h->ev_sys, &channel->receive_event, EV_READABLE);

    return 0;
}

int channel_receive_event(void *carry_data) {
    struct receive_event_data *data = carry_data;
    struct rasta_handle *h = data->h;
    unsigned int mux_channel_count = h->mux.channel_count;

    run_channel_diagnostics(h, mux_channel_count, data->channel->id);

    // channel count might have changed due to removal of channels
    mux_channel_count = h->mux.channel_count;

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive thread", "Channel %d calling receive",
               data->channel->id);

    unsigned char buffer[MAX_DEFER_QUEUE_MSG_SIZE] = {0};
    struct sockaddr_in sender = {0};

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive", "Receive called");

    ssize_t len = receive_callback(&h->mux, data, buffer, &sender);

    if (len == 0) {
        return 0;
    }

    if (len < 0) {
        // TODO: Disable receive event, remove this channel from
        // connected_transport_channels since socket is broken
        // If this is a RaSTA client, try to re-establish a connection somewhere else

        // transport_redial(data->channel);
        return 0;
    }

    int result = receive_packet(h->receive_handle, &h->mux, data->channel, data, &sender, buffer, len);

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive thread", "Channel %d receive done",
               data->channel->id);
    return !!result;
}
