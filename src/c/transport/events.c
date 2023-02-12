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

    // TODO: As a server, we have to maintain a list of known communication partners.
    // Actually, we should initialize the redundancy channels on startup using this knowledge.
    // Each redundancy (and safety/retransmission channel) could use an entirely different config...
    // Using the TCP port, we can already assign the correct redundancy channel from this list.
    // If no such channel is found, reject the connection.

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
    // If channel was connected previously, it may already be added to the linked list
    add_fd_event(data->h->ev_sys, &channel->receive_event, EV_READABLE);

    return 0;
}

int channel_receive_event(void *carry_data) {
    struct receive_event_data *data = carry_data;
    struct rasta_handle *h = data->h;

    run_channel_diagnostics(h, h->mux.channel_count, data->channel->id);

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive", "Channel %d calling receive",
               data->channel->id);

    unsigned char buffer[MAX_DEFER_QUEUE_MSG_SIZE] = {0};
    struct sockaddr_in sender = {0};
    ssize_t len = receive_callback(&h->mux, data, buffer, &sender);

    if (len == 0) {
        // Peer has performed an orderly shutdown
        disable_fd_event(&data->channel->receive_event);
        return 0;
    }

    if (len < 0) {
        // Disable receive event
        disable_fd_event(&data->channel->receive_event);

        // TODO: If this is a RaSTA client, try to re-establish a connection somewhere else
        // transport_redial(data->channel);
        return 0;
    }

    int result = receive_packet(h->receive_handle, &h->mux, data->channel, data, &sender, buffer, len);

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive thread", "Channel %d receive done",
               data->channel->id);
    return !!result;
}
