#include "safety_retransmission.h"
#include "protocol.h"
#include <rasta/rasta.h>
#include <rasta/rasta_lib.h>
#include <rasta/rmemory.h>
#include <rasta/rastahandle.h>
#include "../transport/events.h"
#include "../transport/transport.h"
#include "../retransmission/handlers.h"

void updateTimeoutInterval(long confirmed_timestamp, struct rasta_connection *con, struct RastaConfigInfoSending cfg) {
    unsigned long t_local = cur_timestamp();
    unsigned long t_rtd = t_local + (1000 / sysconf(_SC_CLK_TCK)) - confirmed_timestamp;
    con->t_i = (uint32_t)(cfg.t_max - t_rtd);

    // update the timeout start time
    reschedule_event(&con->timeout_event);
}

void resetDiagnostic(struct rasta_connection *connection) {
    for (unsigned int i = 0; i < connection->diagnostic_intervals_length; i++) {
        connection->diagnostic_intervals[i].message_count = 0;
        connection->diagnostic_intervals[i].t_alive_message_count = 0;
    }
}

void updateDiagnostic(struct rasta_connection *connection, struct RastaPacket *receivedPacket, struct RastaConfigInfoSending cfg, struct rasta_handle *h) {
    unsigned long t_local = cur_timestamp();
    unsigned long t_rtd = t_local + (1000 / sysconf(_SC_CLK_TCK)) - receivedPacket->confirmed_timestamp;
    unsigned long t_alive = t_local - connection->cts_r;
    for (unsigned int i = 0; i < connection->diagnostic_intervals_length; i++) {
        if (connection->diagnostic_intervals[i].interval_start >= t_rtd && connection->diagnostic_intervals[i].interval_end <= t_rtd) {
            // found the sub interval this message can be assigned to
            ++connection->diagnostic_intervals[i].message_count;

            // lies t_alive in interval range, too?
            if (connection->diagnostic_intervals[i].interval_start >= t_alive && connection->diagnostic_intervals[i].interval_end <= t_alive) {
                ++connection->diagnostic_intervals[i].t_alive_message_count;
            }
            break; // we found our interval. Other executions aren't necessary anymore
        }
    }
    ++connection->received_diagnostic_message_count;
    if (connection->received_diagnostic_message_count >= cfg.diag_window) {
        fire_on_diagnostic_notification(sr_create_notification_result(h, connection));
        resetDiagnostic(connection);
    }
}

void sr_add_app_messages_to_buffer(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket *packet) {
    struct RastaMessageData received_data;
    received_data = extractMessageData(packet);

    logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA add to buffer", "received %d application messages", received_data.count);

    for (unsigned int i = 0; i < received_data.count; ++i) {
        rastaApplicationMessage *elem = rmalloc(sizeof(rastaApplicationMessage));
        elem->id = packet->sender_id;
        allocateRastaByteArray(&elem->appMessage, received_data.data_array[i].length);

        rmemcpy(elem->appMessage.bytes, received_data.data_array[i].bytes, received_data.data_array[i].length);
        if (!fifo_push(con->fifo_app_msg, elem)) {
            logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA add to buffer", "discarding data because fifo is full");
        }
        // fire onReceive event
        fire_on_receive(sr_create_notification_result(h->handle, con));

        updateTimeoutInterval(packet->confirmed_timestamp, con, h->config);
        updateDiagnostic(con, packet, h->config, h->handle);
    }
}

/**
 * removes all confirmed messages from the retransmission fifo
 * @param con the connection that is used
 */
void sr_remove_confirmed_messages(struct rasta_receive_handle *h, struct rasta_connection *con) {
    // remove confirmed messages from retransmission fifo
    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA remove confirmed", "confirming messages with SN_PDU <= %lu", (long unsigned int)con->cs_r);

    struct RastaByteArray *elem;
    while ((elem = fifo_pop(con->fifo_retransmission)) != NULL) {
        struct RastaPacket packet = bytesToRastaPacket(*elem, h->hashing_context);
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA remove confirmed", "removing packet with sn = %lu",
                   (long unsigned int)packet.sequence_number);

        // message is confirmed when CS_R - SN_PDU >= 0
        // equivalent to SN_PDU <= CS_R
        if (packet.sequence_number == con->cs_r) {
            // this packet has the last same sequence number as the confirmed sn, i.e. the next packet in the queue's
            // SN_PDU will be bigger than CS_R (because of FIFO property of mqueue)
            // that means we removed all confirmed messages and have to leave the loop to stop removing packets
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA remove confirmed", "last confirmed packet removed");

            freeRastaByteArray(elem);
            freeRastaByteArray(&packet.data);
            rfree(elem);

            break;
        }

        freeRastaByteArray(elem);
        freeRastaByteArray(&packet.data);
        rfree(elem);
    }
}

/* ----- processing of received packet types ----- */

/**
 * calculates cts_in_seq for the given @p packet
 * @param con the connection that is used
 * @param packet the packet
 * @return cts_in_seq (bool)
 */
int sr_cts_in_seq(struct rasta_connection *con, struct RastaConfigInfoSending cfg, struct RastaPacket *packet) {

    if (packet->type == RASTA_TYPE_HB || packet->type == RASTA_TYPE_DATA || packet->type == RASTA_TYPE_RETRDATA) {
        // Workaround rs 05.04.22
        // what should happen if cts_r is 0 (i.e. no packet received yet)
        if (con->cts_r == 0) {
            return 1;
        }

        // cts_in_seq := 0 <= CTS_PDU - CTS_R < t_i
        if (packet->confirmed_timestamp < con->cts_r) {
            return 0;
        }
        return (packet->confirmed_timestamp - con->cts_r) < cfg.t_max;
    } else {
        // for any other type return always true
        return 1;
    }
}

/**
 * calculates sn_in_seq for the given @p packet
 * @param con the connection that is used
 * @param packet the packet
 * @return sn_in_seq (bool)
 */
int sr_sn_in_seq(struct rasta_connection *con, struct RastaPacket *packet) {
    if (packet->type == RASTA_TYPE_CONNREQ || packet->type == RASTA_TYPE_CONNRESP ||
        packet->type == RASTA_TYPE_RETRRESP || packet->type == RASTA_TYPE_DISCREQ) {
        // return always true
        return 1;
    } else {
        // check sn_in_seq := sn_r == sn_pdu
        return (con->sn_r == packet->sequence_number);
    }
}

/**
 * Checks the sequence number range as in 5.5.3.2
 * @param con connection that is used
 * @param packet the packet
 * @return 1 if the sequency number of the @p packet is in range
 */
int sr_sn_range_valid(struct rasta_connection *con, struct RastaConfigInfoSending cfg, struct RastaPacket *packet) {
    // for types ConReq, ConResp and RetrResp return true
    if (packet->type == RASTA_TYPE_CONNREQ || packet->type == RASTA_TYPE_CONNRESP || packet->type == RASTA_TYPE_RETRRESP) {
        return 1;
    }

    // else
    // seq. nr. in range when 0 <= SN_PDU - SN_R <= N_SENDMAX * 10
    return ((packet->sequence_number >= con->sn_r) &&
            (packet->sequence_number - con->sn_r) <= (cfg.send_max * 10));
}

/**
 * checks the confirmed sequence number integrity as in 5.5.4
 * @param con connection that is used
 * @param packet the packet
 * @return 1 if the integrity of the confirmed sequency number is confirmed, 0 otherwise
 */
int sr_cs_valid(struct rasta_connection *con, struct RastaPacket *packet) {
    if (packet->type == RASTA_TYPE_CONNREQ) {
        // initial CS_PDU has to be 0
        return (packet->confirmed_sequence_number == 0);
    } else if (packet->type == RASTA_TYPE_CONNRESP) {
        // has to be identical to last used (sent) seq. nr.
        return (packet->confirmed_sequence_number == (con->sn_t - 1));
    } else {
        // 0 <= CS_PDU - CS_R < SN_T - CS_R
        return ((packet->confirmed_sequence_number >= con->cs_r) &&
                (packet->confirmed_sequence_number - con->cs_r) < (con->sn_t - con->cs_r));
    }
}

/**
 * checks the packet authenticity as in 5.5.2 2)
 * @param con connection that is used
 * @param packet the packet
 * @return 1 if sender and receiver of the @p packet are authentic, 0 otherwise
 */
int sr_message_authentic(struct rasta_connection *con, struct RastaPacket *packet) {
    return (packet->sender_id == con->remote_id && packet->receiver_id == con->my_id);
}

int sr_check_packet(struct rasta_connection *con, struct logger_t *logger, struct RastaConfigInfoSending cfg, struct RastaPacket *receivedPacket, char *location) {
    // check received packet (5.5.2)
    if (!(receivedPacket->checksum_correct &&
          sr_message_authentic(con, receivedPacket) &&
          sr_sn_range_valid(con, cfg, receivedPacket) &&
          sr_cs_valid(con, receivedPacket) &&
          sr_sn_in_seq(con, receivedPacket) &&
          sr_cts_in_seq(con, cfg, receivedPacket))) {
        // something is invalid -> connection failure
        logger_log(logger, LOG_LEVEL_INFO, location, "received packet invalid");

        logger_log(logger, LOG_LEVEL_DEBUG, location, "checksum = %d", receivedPacket->checksum_correct);
        logger_log(logger, LOG_LEVEL_DEBUG, location, "authentic = %d", sr_message_authentic(con, receivedPacket));
        logger_log(logger, LOG_LEVEL_DEBUG, location, "sn_range_valid = %d", sr_sn_range_valid(con, cfg, receivedPacket));
        logger_log(logger, LOG_LEVEL_DEBUG, location, "cs_valid = %d", sr_cs_valid(con, receivedPacket));
        logger_log(logger, LOG_LEVEL_DEBUG, location, "sn_in_seq = %d", sr_sn_in_seq(con, receivedPacket));
        logger_log(logger, LOG_LEVEL_DEBUG, location, "cts_in_seq = %d", sr_cts_in_seq(con, cfg, receivedPacket));

        return 0;
    }

    return 1;
}

void sr_reset_connection(struct rasta_connection *connection, unsigned long id, struct RastaConfigInfoGeneral info) {
    connection->remote_id = (uint32_t)id;
    connection->current_state = RASTA_CONNECTION_CLOSED;
    connection->my_id = (uint32_t)info.rasta_id;
    connection->network_id = (uint32_t)info.rasta_network;
    connection->connected_recv_buffer_size = -1;
    connection->hb_locked = 1;
    connection->hb_stopped = 0;

    // set all error counters to 0
    struct rasta_error_counters error_counters;
    error_counters.address = 0;
    error_counters.cs = 0;
    error_counters.safety = 0;
    error_counters.sn = 0;
    error_counters.type = 0;

    connection->errors = error_counters;
}

void sr_close_connection(struct rasta_connection *connection, struct rasta_handle *handle, redundancy_mux *mux,
                         struct RastaConfigInfoGeneral info, rasta_disconnect_reason reason, unsigned short details) {
    if (connection->current_state == RASTA_CONNECTION_DOWN || connection->current_state == RASTA_CONNECTION_CLOSED) {
        sr_reset_connection(connection, connection->remote_id, info);

        redundancy_mux_remove_channel(&handle->mux, connection->remote_id);

        // fire connection state changed event
        fire_on_connection_state_change(sr_create_notification_result(handle, connection));
    } else {
        // need to send DiscReq
        sr_reset_connection(connection, connection->remote_id, info);
        sendDisconnectionRequest(mux, connection, reason, details);

        connection->current_state = RASTA_CONNECTION_CLOSED;

        redundancy_mux_remove_channel(&handle->mux, connection->remote_id);

        // fire connection state changed event
        fire_on_connection_state_change(sr_create_notification_result(handle, connection));
    }
}

void sr_diagnostic_interval_init(struct rasta_connection *connection, struct RastaConfigInfoSending cfg) {
    connection->received_diagnostic_message_count = 0;

    unsigned int diagnostic_interval_length = cfg.t_max / DIAGNOSTIC_INTERVAL_SIZE;
    if (cfg.t_max % DIAGNOSTIC_INTERVAL_SIZE > 0) {
        ++diagnostic_interval_length;
    }
    connection->diagnostic_intervals = rmalloc(diagnostic_interval_length * sizeof(struct diagnostic_interval));
    connection->diagnostic_intervals_length = diagnostic_interval_length;
    for (unsigned int i = 0; i < diagnostic_interval_length; i++) {
        struct diagnostic_interval sub_interval;

        sub_interval.interval_start = DIAGNOSTIC_INTERVAL_SIZE * i;
        // last interval_end could be greater than T_MAX but we don't care. Every connection will be closed when you exceed T_MAX
        sub_interval.interval_end = sub_interval.interval_start + DIAGNOSTIC_INTERVAL_SIZE;
        sub_interval.message_count = 0;
        sub_interval.t_alive_message_count = 0;

        connection->diagnostic_intervals[i] = sub_interval;
    }
}

void sr_init_connection(struct rasta_connection *connection, unsigned long id, struct RastaConfigInfoGeneral info, struct RastaConfigInfoSending cfg, struct logger_t *logger, rasta_role role) {
    (void)logger;
    sr_reset_connection(connection, id, info);
    connection->role = role;

    // initalize diagnostic interval and store it in connection
    sr_diagnostic_interval_init(connection, cfg);

    // create receive queue
    connection->fifo_app_msg = fifo_init(cfg.send_max);

    // init retransmission fifo
    connection->fifo_retransmission = fifo_init(MAX_QUEUE_SIZE);

    // create send queue
    connection->fifo_send = fifo_init(2 * cfg.max_packet);

    // reset last rekeying time
#ifdef ENABLE_OPAQUE
    connection->kex_state.last_key_exchanged_millis = 0;
#endif
}

void sr_retransmit_data(struct rasta_receive_handle *h, struct rasta_connection *connection) {
    /**
     *  * retransmit messages in queue
     */

    // prepare Array Buffer
    struct RastaByteArray packets[MAX_QUEUE_SIZE];

    int buffer_n = 0; // how many valid elements are in the buffer
    buffer_n = fifo_get_size(connection->fifo_retransmission);
    logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "found %d unconfirmed packets", buffer_n);

    // get all packets and store them in the buffer
    for (int j = 0; j < buffer_n; ++j) {
        struct RastaByteArray *element;
        element = fifo_pop(connection->fifo_retransmission);

        allocateRastaByteArray(&packets[j], element->length);
        rmemcpy(packets[j].bytes, element->bytes, element->length);

        freeRastaByteArray(element);
        rfree(element);
    }

    // re-open fifo in write mode
    // now retransmit each packet in the buffer with new sequence numbers
    for (int i = 0; i < buffer_n; i++) {
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "retransmit packet %d", i);

        // retrieve retransmission data to
        struct RastaPacket old_p = bytesToRastaPacket(packets[i], h->hashing_context);
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "convert packet %d to packet structure", i);

        struct RastaMessageData app_messages = extractMessageData(&old_p);
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "extract data from packet %d ", i);

        // create new packet for retransmission
        struct RastaPacket data = createRetransmittedDataMessage(connection->remote_id, connection->my_id, connection->sn_t,
                                                                 connection->cs_t, cur_timestamp(), connection->ts_r,
                                                                 app_messages, h->hashing_context);
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "created retransmission packet %d ", i);

        struct RastaByteArray new_p = rastaModuleToBytes(data, h->hashing_context);

        // add packet to retrFifo again
        struct RastaByteArray *to_fifo = rmalloc(sizeof(struct RastaByteArray));
        allocateRastaByteArray(to_fifo, new_p.length);
        rmemcpy(to_fifo->bytes, new_p.bytes, new_p.length);
        if (fifo_push(connection->fifo_retransmission, to_fifo)) {
            logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "added packet %d to queue", i);
        } else {
            logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA retransmission", "could not add packet to full queue");
        }

        // send packet
        redundancy_mux_send(h->mux, data);
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA retransmission", "retransmitted packet with old sn=%lu",
                   (long unsigned int)old_p.sequence_number);

        // increase sn_t
        connection->sn_t = connection->sn_t + 1;

        // set last message ts
        reschedule_event(&connection->send_heartbeat_event);

        // free allocated memory of current packet
        freeRastaByteArray(&packets[i]);
        freeRastaByteArray(&new_p);
        freeRastaByteArray(&old_p.data);
    }

    // close retransmission with heartbeat
    sendHeartbeat(h->mux, connection, 1);
}

unsigned int sr_retransmission_queue_item_count( struct rasta_connection *connection) {
    return fifo_get_size(connection->fifo_retransmission);
}

unsigned int sr_send_queue_item_count(struct rasta_connection *connection) {
    return fifo_get_size(connection->fifo_send);
}

void rasta_socket(struct rasta_handle *handle, struct RastaConfigInfo *config, struct logger_t *logger) {
    rasta_handle_init(handle, config, logger);

    // init the redundancy layer
    redundancy_mux_init_config(&handle->mux, handle->redlogger, handle->config);

    //  register redundancy layer diagnose notification handler
    handle->mux.notifications.on_diagnostics_available = handle->notifications.on_redundancy_diagnostic_notification;
}

void sr_listen(struct rasta_handle *h) {
    redundancy_mux_listen_channels(&h->mux, &h->config.tls);

    // Register accept events

    int accept_event_data_len = h->mux.port_count;
    fd_event *accept_events = rmalloc(sizeof(fd_event) * accept_event_data_len);
    struct accept_event_data *accept_event_data = rmalloc(sizeof(struct accept_event_data) * accept_event_data_len);

    for (int i = 0; i < accept_event_data_len; i++) {
        memset(&accept_events[i], 0, sizeof(fd_event));
        accept_events[i].carry_data = accept_event_data + i;

        accept_events[i].callback = channel_accept_event;
        accept_events[i].fd = h->mux.transport_sockets[i].file_descriptor;
        accept_events[i].enabled = 1;

        accept_event_data[i].socket = &h->mux.transport_sockets[i];
        accept_event_data[i].event = accept_events + i;
        accept_event_data[i].h = h;

        // TODO: accept_events and accept_event_data is leaked
        add_fd_event(h->ev_sys, &accept_events[i], EV_READABLE);
    }
}

// HACK
int data_send_event(void *carry_data);

void sr_send(struct rasta_handle *h, unsigned long remote_id, struct RastaMessageData app_messages) {

    struct rasta_connection *con;
    for (con = h->first_con; con; con = con->linkedlist_next) {
        if (con->remote_id == remote_id)
            break;
    }

    if (con == 0)
        return;

    if (con->current_state == RASTA_CONNECTION_UP) {
        if (app_messages.count > h->config.sending.max_packet) {
            // to many application messages
            logger_log(&h->logger, LOG_LEVEL_ERROR, "RaSTA send", "too many application messages to send in one packet. Maximum is %d",
                       h->config.sending.max_packet);
            // do nothing and leave method with error code 2
            return;
        }

        for (unsigned int i = 0; i < app_messages.count; ++i) {
            struct RastaByteArray msg;
            msg = app_messages.data_array[i];

            // push into queue
            struct RastaByteArray *to_fifo = rmalloc(sizeof(struct RastaByteArray));
            allocateRastaByteArray(to_fifo, msg.length);
            rmemcpy(to_fifo->bytes, msg.bytes, msg.length);

            if (fifo_full(con->fifo_send)) {
                // Flush, send queued messages now
                data_send_event(h->send_handle);
            }

            if (!fifo_push(con->fifo_send, to_fifo)) {
                logger_log(&h->logger, LOG_LEVEL_INFO, "RaSTA send", "could not insert message into send queue");
            }
        }

        logger_log(&h->logger, LOG_LEVEL_INFO, "RaSTA send", "data in send queue");

    } else if (con->current_state == RASTA_CONNECTION_CLOSED || con->current_state == RASTA_CONNECTION_DOWN) {
        // nothing to do besides changing state to closed
        con->current_state = RASTA_CONNECTION_CLOSED;

        // fire connection state changed event
        fire_on_connection_state_change(sr_create_notification_result(h, con));
    } else {
        logger_log(&h->logger, LOG_LEVEL_ERROR, "RaSTA send", "service not allowed");

        // disconnect and close
        sendDisconnectionRequest(&h->mux, con, RASTA_DISC_REASON_SERVICENOTALLOWED, 0);
        con->current_state = RASTA_CONNECTION_CLOSED;

        // fire connection state changed event
        fire_on_connection_state_change(sr_create_notification_result(h, con));

        // leave with error code 1
        return;
    }
}

rastaApplicationMessage sr_get_received_data(struct rasta_handle *h, struct rasta_connection *connection) {
    rastaApplicationMessage message;
    rastaApplicationMessage *element;

    element = fifo_pop(connection->fifo_app_msg);

    message.id = element->id;
    message.appMessage = element->appMessage;

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA retrieve", "application message with l %d", message.appMessage.length);
    // logger_log(&h->logger, LOG_LEVEL_DEBUG, "RETRIEVE DATA", "Convert bytes to packet");

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA retrieve", "Packets in fifo remaining: %d", fifo_get_size(connection->fifo_app_msg));

    rfree(element);

    // struct RastaPacket packet = bytesToRastaPacket(msg);
    // return packet;
    return message;
}

/**
 * cleanup a connection after a disconnect
 * @param h
 * @param remote_id
 */
void sr_disconnect(struct rasta_handle *h, struct rasta_connection *con) {
    logger_log(&h->logger, LOG_LEVEL_INFO, "RaSTA connection", "disconnected %X", con->remote_id);

    sr_close_connection(con, h, &h->mux, h->config.general, RASTA_DISC_REASON_USERREQUEST, 0);

    remove_timed_event(h->ev_sys, &con->timeout_event);
    remove_timed_event(h->ev_sys, &con->send_heartbeat_event);
    remove_connection_from_list(h, con);
#ifdef ENABLE_OPAQUE
    if (h->config.kex.rekeying_interval_ms) {
        remove_timed_event(h->ev_sys, &con->rekeying_event);
    }
#endif

    h->user_handles->on_disconnect(con, con);
}

void sr_cleanup(struct rasta_handle *h) {
    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA Cleanup", "Cleanup called");

    if (h->user_handles->on_rasta_cleanup) {
        h->user_handles->on_rasta_cleanup();
    }

    for (struct rasta_connection *connection = h->first_con; connection; connection = connection->linkedlist_next) {
        // free memory allocated for diagnostic intervals
        rfree(connection->diagnostic_intervals);

        // free FIFOs
        fifo_destroy(connection->fifo_app_msg);
        fifo_destroy(connection->fifo_send);
        fifo_destroy(connection->fifo_retransmission);
    }

    // set notification pointers to NULL
    h->notifications.on_receive = NULL;
    h->notifications.on_connection_state_change = NULL;
    h->notifications.on_diagnostic_notification = NULL;
    h->notifications.on_disconnection_request_received = NULL;
    h->notifications.on_redundancy_diagnostic_notification = NULL;

    // close mux
    redundancy_mux_close(&h->mux);

    rfree(h->receive_handle);
    rfree(h->send_handle);
    rfree(h->heartbeat_handle);

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA Cleanup", "Cleanup done");

    logger_destroy(&h->logger);
}

#ifdef ENABLE_OPAQUE
bool sr_rekeying_skipped(struct rasta_connection *connection, struct RastaConfigKex *kexConfig) {
    uint64_t current_time;
    if (connection->current_state == RASTA_CONNECTION_KEX_REQ) {
        // already waiting for key exchange
        return false;
    }

    if (connection->role != RASTA_ROLE_SERVER) {
        // client cannot expect to receive key requests from server
        return false;
    }

    if (!kexConfig->rekeying_interval_ms || !connection->kex_state.last_key_exchanged_millis) {
        // no rekeying or no initial time yet
        return false;
    }

    current_time = get_current_time_ms();

    return current_time - connection->kex_state.last_key_exchanged_millis > REKEYING_ALLOWED_DELAY_MS + kexConfig->rekeying_interval_ms;
}
#else
bool sr_rekeying_skipped(struct rasta_connection *connection, struct RastaConfigKex *kexConfig) {
    // no rekeying possible without key exchange
    (void)connection;
    (void)kexConfig;
    return false;
}
#endif

// TODO: Find a suitable header file for this
int rasta_receive(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket *receivedPacket);

void sr_receive(struct rasta_receive_handle *h, struct RastaPacket *receivedPacket) {
    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA RECEIVE", "Received packet %d from %d to %d %u", receivedPacket->type, receivedPacket->sender_id, receivedPacket->receiver_id, receivedPacket->length);

    struct rasta_connection *con;
    for (con = h->handle->first_con; con; con = con->linkedlist_next) {
        if (con->remote_id == receivedPacket->sender_id) break;
    }

    // new client request
    if (receivedPacket->type == RASTA_TYPE_CONNREQ) {
        con = handle_conreq(h, con, receivedPacket);

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    if (con == NULL) {
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA RECEIVE", "Received packet (%d) from unknown source %d", receivedPacket->type, receivedPacket->sender_id);
        // received packet from unknown source
        // TODO: can these packets be ignored?

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    // handle response
    if (receivedPacket->type == RASTA_TYPE_CONNRESP) {
        handle_conresp(h, con, receivedPacket);

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA RECEIVE", "Checking packet ...");

    // check message checksum
    if (!receivedPacket->checksum_correct) {
        logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA RECEIVE", "Received packet checksum incorrect");
        // increase safety error counter
        con->errors.safety++;

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    // check for plausible ids
    if (!sr_message_authentic(con, receivedPacket)) {
        logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA RECEIVE", "Received packet invalid sender/receiver");
        // increase address error counter
        con->errors.address++;

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    // check sequency number range
    if (!sr_sn_range_valid(con, h->config, receivedPacket)) {
        logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA RECEIVE", "Received packet sn range invalid");

        // invalid -> increase error counter and discard packet
        con->errors.sn++;

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    // check confirmed sequence number
    if (!sr_cs_valid(con, receivedPacket)) {
        logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA RECEIVE", "Received packet cs invalid");

        // invalid -> increase error counter and discard packet
        con->errors.cs++;

        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    if (sr_rekeying_skipped(con, &h->handle->config.kex)) {
        logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA KEX", "Did not receive key exchange request for rekeying in time at %" PRIu64 " - disconnecting!", get_current_time_ms());
        sr_close_connection(con, h->handle, h->mux, h->info, RASTA_DISC_REASON_TIMEOUT, 0);
        freeRastaByteArray(&receivedPacket->data);
        return;
    }

    rasta_receive(h, con, receivedPacket);
}
