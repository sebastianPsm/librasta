#include <rasta/rasta_lib.h>

#include <memory.h>
#include <rasta/rasta.h>
#include <stdbool.h>

void rasta_lib_init_configuration(rasta_lib_configuration_t user_configuration, rasta_config_info *config, struct logger_t *logger) {
    memset(user_configuration, 0, sizeof(rasta_lib_configuration_t));
    rasta_socket(&user_configuration->h, config, logger);
    memset(&user_configuration->rasta_lib_event_system, 0, sizeof(user_configuration->rasta_lib_event_system));
    memset(&user_configuration->callback, 0, sizeof(user_configuration->callback));
    user_configuration->h.user_handles = &user_configuration->callback;

    struct rasta_handle *h = &user_configuration->h;
    event_system *event_system = &user_configuration->rasta_lib_event_system;
    h->ev_sys = event_system;
}
