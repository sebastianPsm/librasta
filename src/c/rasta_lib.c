#include <rasta/rasta_lib.h>

#include <memory.h>
#include <stdbool.h>
#include <rasta/rasta.h>
#include <rasta/rmemory.h>
#include "transport/events.h"
#include "retransmission/protocol.h"
#include "retransmission/safety_retransmission.h"

int event_connection_expired(void *carry_data);
void init_connection_timeout_event(timed_event *ev, struct timed_event_data *carry_data,
                                   struct rasta_connection *connection) {
    memset(ev, 0, sizeof(timed_event));
    ev->callback = event_connection_expired;
    ev->carry_data = carry_data;
    ev->interval = connection->heartbeat_handle.config.t_max * 1000000lu;
    carry_data->handle = &connection->heartbeat_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

int heartbeat_send_event(void *carry_data);
void init_send_heartbeat_event(timed_event *ev, struct timed_event_data *carry_data,
                               struct rasta_connection *connection) {
    memset(ev, 0, sizeof(timed_event));
    ev->callback = heartbeat_send_event;
    ev->carry_data = carry_data;
    ev->interval = connection->heartbeat_handle.config.t_h * 1000000lu;
    carry_data->handle = &connection->heartbeat_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

int send_timed_key_exchange(void *arg);
void init_send_key_exchange_event(timed_event *ev, struct timed_event_data *carry_data,
                                  struct rasta_connection *connection) {
    ev->callback = send_timed_key_exchange;
    ev->carry_data = carry_data;
    ev->interval = connection->config->kex.rekeying_interval_ms * NS_PER_MS;
    // add some headroom for computation and communication
    ev->interval /= 2;
    carry_data->handle = &connection->receive_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

void init_connection_events(struct rasta_handle *h, struct rasta_connection *connection) {
    init_connection_timeout_event(&connection->timeout_event, &connection->timeout_carry_data, connection);
    init_send_heartbeat_event(&connection->send_heartbeat_event, &connection->timeout_carry_data, connection);
    add_timed_event(h->ev_sys, &connection->timeout_event);
    add_timed_event(h->ev_sys, &connection->send_heartbeat_event);
#ifdef ENABLE_OPAQUE
    if (connection->role == RASTA_ROLE_CLIENT && h->config.kex.rekeying_interval_ms) {
        init_send_key_exchange_event(&connection->rekeying_event, &connection->rekeying_carry_data, connection);
        add_timed_event(h->ev_sys, &connection->rekeying_event);
    }
#endif
}

void rasta_lib_init_configuration(rasta_lib_configuration_t user_configuration, rasta_config_info *config, struct logger_t *logger, rasta_connection_config *connections, size_t connections_length) {
    memset(user_configuration, 0, sizeof(rasta_lib_configuration_t));
    rasta_socket(&user_configuration->h, config, logger);
    memset(&user_configuration->rasta_lib_event_system, 0, sizeof(user_configuration->rasta_lib_event_system));
    memset(&user_configuration->callback, 0, sizeof(user_configuration->callback));
    user_configuration->h.user_handles = &user_configuration->callback;

    struct rasta_handle *h = &user_configuration->h;
    event_system *event_system = &user_configuration->rasta_lib_event_system;
    h->ev_sys = event_system;

    // This is the place where we malloc
    redundancy_mux_allocate_channels(h, &h->mux, connections, connections_length);

    h->rasta_connections = rmalloc(sizeof(rasta_connection) * connections_length);
    for (unsigned i = 0; i < connections_length; i++) {
        // TODO:
        sr_init_connection(&h->rasta_connections[i], connections[i].rasta_id, RASTA_ROLE_CLIENT, config);
        init_connection_events(h, &h->rasta_connections[i]);
    }
}
