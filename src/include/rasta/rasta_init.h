#pragma once

#ifdef __cplusplus
extern "C" { // only need to export C interface if
             // used by C++ source code
#endif

#include "config.h"

typedef struct rasta rasta;

/**
 * initializes the RaSTA handle and all configured connections
 * @param user_configuration the user configuration containing the handle to initialize
 * @param config the configuration to initialize the handle with
 * @param logger the logger to use
 * @param connections the connections to initialize
 * @param connections_length the length of the connections array
 */
rasta *rasta_lib_init_configuration(rasta_config_info *config, rasta_connection_config *connections, size_t connections_length, log_level log_level, logger_type logger_type);

#ifdef __cplusplus
}
#endif
