#pragma once

#include <rasta/rastahandle.h>
#include <rasta/rastamodule.h>

void handle_kex_request(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_kex_response(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_kex_auth(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
