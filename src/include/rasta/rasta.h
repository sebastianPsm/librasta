#pragma once

#ifdef __cplusplus
extern "C" { // only need to export C interface if
             // used by C++ source code
#endif

#include <stdbool.h>
#include <stddef.h>

#include "config.h"
#include "events.h"
#include "notification.h"
#include "rasta_init.h"
#include "rastarole.h"

typedef struct rasta rasta;
struct rasta_connection;

// The header, which the user will include later.

/**
 * binds a RaSTA instance to the configured IP addresses and ports for the transport channels
 * @param user_configuration the user configuration to be used
 */
bool rasta_bind(rasta *r);

/**
 * Listen on all sockets specified by the given RaSTA handle.
 * @param user_configuration the user configuration containing the socket information
 */
void rasta_listen(rasta *r);

/**
 * Wait for connections on all sockets specified in the user_configuration.
 * @param user_configuration the user configuration containing the socket information
 */
struct rasta_connection *rasta_accept(rasta *r);

/**
 * Connect to another rasta instance
 * @param user_configuration the user configuration of the local RaSTA instance
 * @param id the ID of the remote RaSTA instance to connect to
 */
struct rasta_connection *rasta_connect(rasta *r, unsigned long id);

/**
 * Receive data on a given RaSTA connection
 * @param user_configuration the user configuration of the local RaSTA instance
 * @param connection the connection from which to receive the data
 * @param buf the buffer into which to save the received data
 * @param len the size of buf in bytes
 */
int rasta_recv(rasta *r, struct rasta_connection *connection, void *buf, size_t len);

/**
 * Send data on a given RaSTA connection
 * @param user_configuration the user configuration of the local RaSTA instance
 * @param connection the connection on which to send the data
 * @param buf the buffer from which to read the data to be sent
 * @param len the size of buf in bytes
 */
int rasta_send(rasta *r, struct rasta_connection *connection, void *buf, size_t len);

/**
 * disconnect a connection on request by the user
 * @param connection the connection that should be disconnected
 */
void rasta_disconnect(struct rasta_connection *connection);

/**
 * Cleanup a connection after a disconnect and free assigned ressources.
 * Always use this when a programm terminates, otherwise it may not start again.
 * @param user_configuration the RaSTA lib configuration
 */
void rasta_cleanup(rasta *r);

#ifdef __cplusplus
}
#endif
