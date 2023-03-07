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

    // Previously, I thought:
    // We cannot decide yet which redundancy_channel this transport_channel belongs to.
    // The communication partner has to send some data first.
    // For now, just register the receive event listener for the new connection.

    memset(&channel->receive_event, 0, sizeof(fd_event));
    channel->receive_event.enabled = 1;
    channel->receive_event.carry_data = &channel->receive_event_data;
    channel->receive_event.callback = channel_receive_event;
    channel->receive_event.fd = channel->file_descriptor;

    channel->receive_event_data.channel = channel;
    channel->receive_event_data.h = data->h;

    // TODO: channel might be leaked
    // If channel was connected previously, it may already be added to the linked list
    add_fd_event(data->h->ev_sys, &channel->receive_event, EV_READABLE);

    return 0;
}

int channel_receive_event(void *carry_data) {
    struct receive_event_data *data = carry_data;
    struct rasta_handle *h = data->h;

    unsigned char buffer[MAX_DEFER_QUEUE_MSG_SIZE] = {0};
    struct sockaddr_in sender = {0};
    ssize_t len = receive_callback(&h->mux, data, buffer, &sender);

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender.sin_addr, str, INET_ADDRSTRLEN);

    // Resolve channel by using sender ip and port
    rasta_transport_channel *transport_channel = data->channel;
    if (transport_channel == NULL) {
        for (unsigned i = 0; i < h->mux.channel_count; i++) {
            rasta_redundancy_channel *redundancy_channel = &h->mux.redundancy_channels[i];
            for (unsigned j = 0; j < redundancy_channel->transport_channel_count; j++) {
                rasta_transport_channel *t_transport_channel = &redundancy_channel->transport_channels[j];
                if (strncmp(t_transport_channel->remote_ip_address, str, INET_ADDRSTRLEN) == 0
                        && t_transport_channel->remote_port == ntohs(sender.sin_port)) {
                    transport_channel = t_transport_channel;
                }
            }
        }
    }

    if (transport_channel == NULL) {
        // For UDP and DTLS, this seems to be a new peer
        transport_channel = rmalloc(sizeof(rasta_transport_channel));
        memset(transport_channel, 0, sizeof(rasta_transport_channel));
        transport_channel->id = data->socket->id;
        transport_channel->remote_port = ntohs(sender.sin_port);
        transport_channel->send_callback = send_callback;
        strncpy(transport_channel->remote_ip_address, str, INET_ADDRSTRLEN);
        transport_channel->tls_mode = data->socket->tls_mode;
        transport_channel->file_descriptor = data->socket->file_descriptor;
#ifdef ENABLE_TLS
        transport_channel->tls_state = RASTA_TLS_CONNECTION_READY;
        transport_channel->ctx = data->socket->ctx;
        transport_channel->ssl = data->socket->ssl;
#endif
        // We can regard UDP channels as 'always connected' (no re-dial possible)
        transport_channel->connected = true;

        // TODO: Somewhere, this channel should be freed.
        // Maybe in redmux update connected channels?
    }

    run_channel_diagnostics(h, h->mux.channel_count, transport_channel->id);

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive", "Channel %d calling receive", transport_channel->id);

    if (len == 0) {
        // Peer has performed an orderly shutdown
        if (transport_channel != NULL) {
            disable_fd_event(&transport_channel->receive_event);
        }
        if (data->socket != NULL) {
            disable_fd_event(&data->socket->receive_event);
        }
        return 0;
    }

    if (len < 0) {
        // Connection is broken.
        // Disable receive event
        if (transport_channel != NULL) {
            disable_fd_event(&transport_channel->receive_event);
        }
        if (data->socket != NULL) {
            disable_fd_event(&data->socket->receive_event);
        }

        // TODO: If this is a RaSTA client, try to re-establish a connection somewhere else
        // transport_redial(transport_channel);
        return 0;
    }

    int result = receive_packet(h->receive_handle, &h->mux, transport_channel, &sender, buffer, len);

    logger_log(&h->mux.logger, LOG_LEVEL_DEBUG, "RaSTA RedMux receive thread", "Channel %d receive done",
               transport_channel->id);
    return !!result;
}
