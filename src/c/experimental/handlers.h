#pragma once

#include <rasta/rastahandle.h>
#include <rasta/rastamodule.h>

int handle_kex_request(struct rasta_connection *connection, struct RastaPacket *receivedPacket);
int handle_kex_response(struct rasta_connection *connection, struct RastaPacket *receivedPacket);
int handle_kex_auth(struct rasta_connection *connection, struct RastaPacket *receivedPacket);
