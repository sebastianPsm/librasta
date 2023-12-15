#pragma once

#include <rasta/rastaredundancy.h>

typedef struct redundancy_mux redundancy_mux;
typedef struct redundancy_channel redundancy_channel;

/**
 * connects a given redundancy channel on a given connection and multiplexer.
 * @param mux the multiplexer to which the redundancy channel belongs
 * @param channel the redundancy channel to connect
 */
int redundancy_mux_connect_channel(redundancy_mux *mux, rasta_redundancy_channel *channel);

/**
 * close an existing redundancy channel by closing all its transport channels
 * @param c the RaSTA redundancy channel to close
 */
void redundancy_mux_close_channel(rasta_connection *conn, rasta_redundancy_channel *red_channel);
