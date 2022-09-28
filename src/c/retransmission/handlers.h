#pragma once

#include <rasta/rastahandle.h>
#include <rasta/rastamodule.h>

void handle_discreq(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_hb(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_data(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_retrreq(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_retrresp(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
void handle_retrdata(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
struct rasta_connection *handle_conreq(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket receivedPacket);
struct rasta_connection *handle_conresp(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket receivedPacket);
