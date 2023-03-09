#include <rasta/rasta_lib.h>

#include <memory.h>
#include <rasta/rasta.h>
#include <stdbool.h>
#include "transport/events.h"

// This is the time that packets are deferred for creating multi-packet messages
// See section 5.5.10
#define IO_INTERVAL 10000

void rasta_lib_init_configuration(rasta_lib_configuration_t user_configuration, rasta_config_info *config, struct logger_t *logger) {
    memset(user_configuration, 0, sizeof(rasta_lib_configuration_t));
    rasta_socket(&user_configuration->h, config, logger);
    memset(&user_configuration->rasta_lib_event_system, 0, sizeof(user_configuration->rasta_lib_event_system));
    memset(&user_configuration->callback, 0, sizeof(user_configuration->callback));
    user_configuration->h.user_handles = &user_configuration->callback;

    struct rasta_handle *h = &user_configuration->h;
    event_system *event_system = &user_configuration->rasta_lib_event_system;
    h->ev_sys = event_system;

    // batch outgoing packets
    memset(&h->send_handle->send_event, 0, sizeof(timed_event));
    h->send_handle->send_event.callback = data_send_event;
    h->send_handle->send_event.interval = IO_INTERVAL * 1000lu;
    h->send_handle->send_event.carry_data = h->send_handle;
}
