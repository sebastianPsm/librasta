#include <rasta/rasta_lib.h>

#include <memory.h>
#include <rasta/rasta_new.h>
#include <stdbool.h>

void rasta_lib_init_configuration(rasta_lib_configuration_t user_configuration, struct RastaConfigInfo config, struct logger_t *logger) {
    memset(user_configuration, 0, sizeof(rasta_lib_configuration_t));
    sr_init_handle(&user_configuration->h, config, logger);
    memset(&user_configuration->rasta_lib_event_system, 0, sizeof(user_configuration->rasta_lib_event_system));
    memset(&user_configuration->callback, 0, sizeof(user_configuration->callback));
    user_configuration->h.user_handles = &user_configuration->callback;
}

void rasta_lib_start(rasta_lib_configuration_t user_configuration, int channel_timeout_ms, int listen) {
    sr_begin(&user_configuration->h, &user_configuration->rasta_lib_event_system, channel_timeout_ms, listen);
}
