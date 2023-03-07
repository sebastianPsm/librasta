#pragma once

#include <rasta/event_system.h>

typedef struct rasta_transport_socket rasta_transport_socket;
typedef struct rasta_transport_channel rasta_transport_channel;

int channel_accept_event_tls(void *carry_data);
int channel_accept_event(void *carry_data);
int channel_receive_event(void *carry_data);

struct accept_event_data {
    fd_event *event;
    struct rasta_handle *h;
    rasta_transport_socket *socket;
};

struct receive_event_data {
    struct rasta_handle *h;
    // #ifdef USE_UDP
    rasta_transport_socket *socket;
    // #elif USE_TCP
    rasta_transport_channel *channel;
    // #endif
};
