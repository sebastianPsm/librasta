#pragma once

#include <rasta/event_system.h>
#include <rasta/config.h>
#include <rasta/rastahandle.h>
#include <rasta/logging.h>
#include "messages.h"

void updateTimeoutInterval(long confirmed_timestamp, struct rasta_connection *con, struct RastaConfigInfoSending cfg);
void updateDiagnostic(struct rasta_connection *connection, struct RastaPacket *receivedPacket, struct RastaConfigInfoSending cfg, struct rasta_handle *h);
void sr_add_app_messages_to_buffer(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket *packet);
void sr_remove_confirmed_messages(struct rasta_receive_handle *h, struct rasta_connection *con);
void sr_reset_connection(struct rasta_connection *connection, unsigned long id, struct RastaConfigInfoGeneral info);
void sr_close_connection(struct rasta_connection *connection, struct rasta_handle *handle, redundancy_mux *mux,
                         struct RastaConfigInfoGeneral info, rasta_disconnect_reason reason, unsigned short details);
void sr_diagnostic_interval_init(struct rasta_connection *connection, struct RastaConfigInfoSending cfg);
void sr_init_connection(struct rasta_connection *connection, unsigned long id, struct RastaConfigInfoGeneral info, struct RastaConfigInfoSending cfg, struct logger_t *logger, rasta_role role);
void sr_retransmit_data(struct rasta_receive_handle *h, struct rasta_connection *connection);
void rasta_socket(struct rasta_handle *handle, struct RastaConfigInfo *config, struct logger_t *logger);
void sr_listen(struct rasta_handle *h);
void sr_disconnect(struct rasta_handle *h, struct rasta_connection *con);
void sr_cleanup(struct rasta_handle *h);
int sr_cts_in_seq(struct rasta_connection *con, struct RastaConfigInfoSending cfg, struct RastaPacket *packet);
int sr_sn_in_seq(struct rasta_connection *con, struct RastaPacket *packet);
int sr_sn_range_valid(struct rasta_connection *con, struct RastaConfigInfoSending cfg, struct RastaPacket *packet);
int sr_cs_valid(struct rasta_connection *con, struct RastaPacket *packet);
int sr_message_authentic(struct rasta_connection *con, struct RastaPacket *packet);
int sr_check_packet(struct rasta_connection *con, struct logger_t *logger, struct RastaConfigInfoSending cfg, struct RastaPacket *receivedPacket, char *location);
unsigned int sr_retransmission_queue_item_count(struct rasta_connection *connection);
unsigned int sr_send_queue_item_count(struct rasta_connection *connection);
int sr_receive(struct rasta_receive_handle *h, struct RastaPacket *receivedPacket);
void sr_set_receive_buffer(void *buf, size_t len);
size_t sr_get_received_data_len();
