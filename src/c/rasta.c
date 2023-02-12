#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <rasta/config.h>
#include <rasta/event_system.h>
#include <rasta/rasta.h>
#include <rasta/rasta_lib.h>
#include <rasta/rastahandle.h>
#include <rasta/rastaredundancy.h>
#include <rasta/rmemory.h>

#include "experimental/handlers.h"
#include "retransmission/handlers.h"
#include "retransmission/messages.h"
#include "retransmission/protocol.h"
#include "retransmission/safety_retransmission.h"

int event_connection_expired(void *carry_data);
void init_connection_timeout_event(timed_event *ev, struct timed_event_data *carry_data,
                                   struct rasta_connection *connection, struct rasta_handle *h) {
    memset(ev, 0, sizeof(timed_event));
    ev->callback = event_connection_expired;
    ev->carry_data = carry_data;
    ev->interval = h->heartbeat_handle->config.t_max * 1000000lu;
    carry_data->handle = h->heartbeat_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

int heartbeat_send_event(void *carry_data);
void init_send_heartbeat_event(timed_event *ev, struct timed_event_data *carry_data,
                               struct rasta_connection *connection, struct rasta_handle *h) {
    memset(ev, 0, sizeof(timed_event));
    ev->callback = heartbeat_send_event;
    ev->carry_data = carry_data;
    ev->interval = h->heartbeat_handle->config.t_h * 1000000lu;
    carry_data->handle = h->heartbeat_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

int send_timed_key_exchange(void *arg);
void init_send_key_exchange_event(timed_event *ev, struct timed_event_data *carry_data,
                                  struct rasta_connection *connection, struct rasta_handle *h) {
    ev->callback = send_timed_key_exchange;
    ev->carry_data = carry_data;
    ev->interval = h->config.kex.rekeying_interval_ms * NS_PER_MS;
    // add some headroom for computation and communication
    ev->interval /= 2;
    carry_data->handle = h->receive_handle;
    carry_data->connection = connection;
    enable_timed_event(ev);
}

void init_connection_events(struct rasta_handle *h, struct rasta_connection *connection) {
    init_connection_timeout_event(&connection->timeout_event, &connection->timeout_carry_data, connection, h);
    init_send_heartbeat_event(&connection->send_heartbeat_event, &connection->timeout_carry_data, connection, h);
    add_timed_event(h->ev_sys, &connection->timeout_event);
    add_timed_event(h->ev_sys, &connection->send_heartbeat_event);
#ifdef ENABLE_OPAQUE
    if (connection->role == RASTA_ROLE_CLIENT && h->config.kex.rekeying_interval_ms) {
        init_send_key_exchange_event(&connection->rekeying_event, &connection->rekeying_carry_data, connection, h);
        add_timed_event(h->ev_sys, &connection->rekeying_event);
    }
#endif
}

/**
 * send a Key Exchange Request to the specified host
 * @param connection the connection which should be used
 * @param host the host where the HB will be sent to
 * @param port the port where the HB will be sent to
 */
void send_KexRequest(redundancy_mux *mux, struct rasta_connection *connection, struct rasta_receive_handle *h) {
#ifdef ENABLE_OPAQUE
    struct RastaPacket hb = createKexRequest(connection->remote_id, connection->my_id, connection->sn_t,
                                             connection->cs_t, cur_timestamp(), connection->ts_r,
                                             &mux->sr_hashing_context, h->handle->config.kex.psk, &connection->kex_state, h->logger);

    if (!connection->kex_state.last_key_exchanged_millis && h->handle->config.kex.rekeying_interval_ms) {
        // first key exchanged - need to enable periodic rekeying
        init_send_key_exchange_event(&connection->rekeying_event, &connection->rekeying_carry_data, connection, h->handle);
        add_timed_event(h->handle->ev_sys, &connection->rekeying_event);
    } else {
        logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA KEX", "Rekeying at %" PRIu64, get_current_time_ms());
    }

    redundancy_mux_send(mux, hb);

    connection->sn_t = connection->sn_t + 1;

    connection->kex_state.last_key_exchanged_millis = get_current_time_ms();
    connection->current_state = RASTA_CONNECTION_KEX_RESP;
#else
    // should never be called
    (void)mux;
    (void)connection;
    (void)h;
    abort();
#endif
}

int send_timed_key_exchange(void *arg) {
#ifdef ENABLE_OPAQUE
    struct timed_event_data *event_data = (struct timed_event_data *)arg;
    struct rasta_receive_handle *handle = (struct rasta_receive_handle *)event_data->handle;
    send_KexRequest(handle->mux, event_data->connection, handle);
    // call periodically
    reschedule_event(&event_data->connection->rekeying_event);
#else
    // should never be called
    (void)arg;
#endif
    return 0;
}

int rasta_receive(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket *receivedPacket) {
    switch (receivedPacket->type) {
        case RASTA_TYPE_RETRDATA:
            return handle_retrdata(h, con, receivedPacket);
        case RASTA_TYPE_DATA:
            return handle_data(h, con, receivedPacket);
        case RASTA_TYPE_RETRREQ:
            return handle_retrreq(h, con, receivedPacket);
        case RASTA_TYPE_RETRRESP:
            return handle_retrresp(h, con, receivedPacket);
        case RASTA_TYPE_DISCREQ:
            return handle_discreq(h, con, receivedPacket);
        case RASTA_TYPE_HB:
            return handle_hb(h, con, receivedPacket);
#ifdef ENABLE_OPAQUE
        case RASTA_TYPE_KEX_REQUEST:
            return handle_kex_request(h, con, receivedPacket);
        case RASTA_TYPE_KEX_RESPONSE:
            return handle_kex_response(h, con, receivedPacket);
        case RASTA_TYPE_KEX_AUTHENTICATION:
            return handle_kex_auth(h, con, receivedPacket);
#endif
        default:
            logger_log(h->logger, LOG_LEVEL_ERROR, "RaSTA RECEIVE", "Received unexpected packet type %d", receivedPacket->type);
            // increase type error counter
            con->errors.type++;
            break;
    }
    return 0;
}

int event_connection_expired(void *carry_data) {
    struct timed_event_data *data = carry_data;
    struct rasta_heartbeat_handle *h = (struct rasta_heartbeat_handle *)data->handle;
    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HEARTBEAT", "T_i timer expired - send DisconnectionRequest");

    struct rasta_connection *connection = data->connection;
    // so check if connection is valid

    if (connection == NULL || connection->hb_locked) {
        return 0;
    }

    // connection is valid, check current state
    if (connection->current_state == RASTA_CONNECTION_UP || connection->current_state == RASTA_CONNECTION_RETRREQ || connection->current_state == RASTA_CONNECTION_RETRRUN) {

        // fire heartbeat timeout event
        fire_on_heartbeat_timeout(sr_create_notification_result(h->handle, connection));

        // T_i expired -> close connection
        sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_TIMEOUT, 0);
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HEARTBEAT", "T_i timer expired - \033[91mdisconnected\033[0m");
    }

    disable_timed_event(&connection->send_heartbeat_event);
    disable_timed_event(&connection->timeout_event);
    return 1;
}

int heartbeat_send_event(void *carry_data) {
    struct timed_event_data *data = carry_data;
    struct rasta_heartbeat_handle *h = (struct rasta_heartbeat_handle *)data->handle;

    struct rasta_connection *connection = data->connection;

    if (connection == NULL || connection->hb_locked) {
        return 0;
    }

    // connection is valid, check current state
    if (connection->current_state == RASTA_CONNECTION_UP || connection->current_state == RASTA_CONNECTION_RETRREQ || connection->current_state == RASTA_CONNECTION_RETRRUN) {
        sendHeartbeat(h->mux, connection, 0);

        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HEARTBEAT", "Heartbeat sent to %d", connection->remote_id);
    }

    return 0;
}

// TODO: split up this mess of a function
int data_send_event(void *carry_data) {
    struct rasta_sending_handle *h = carry_data;

    for (struct rasta_connection *con = h->handle->first_con; con; con = con->linkedlist_next) {

        if (con->current_state == RASTA_CONNECTION_DOWN || con->current_state == RASTA_CONNECTION_CLOSED) {
            continue;
        }

        unsigned int retransmission_backlog_size = sr_retransmission_queue_item_count(con);
        // Because of this condition, this method does not reliably free up space in the send queue.
        // However, we need to pass on backpressure to the caller...
        if (retransmission_backlog_size <= MAX_QUEUE_SIZE) {
            unsigned int send_backlog_size = sr_send_queue_item_count(con);

            if (send_backlog_size > 0) {
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA send handler", "Messages waiting to be sent: %d",
                           send_backlog_size);

                con->hb_stopped = 1;
                con->is_sending = 1;

                struct RastaMessageData app_messages;
                struct RastaByteArray msg;

                if (send_backlog_size >= h->config.max_packet) {
                    send_backlog_size = h->config.max_packet;
                }
                allocateRastaMessageData(&app_messages, send_backlog_size);

                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA send handler",
                           "Sending %d application messages from queue",
                           send_backlog_size);

                for (unsigned int i = 0; i < send_backlog_size; i++) {

                    struct RastaByteArray *elem;
                    elem = fifo_pop(con->fifo_send);
                    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA send handler",
                               "Adding application message to data packet");

                    allocateRastaByteArray(&msg, elem->length);
                    msg.bytes = rmemcpy(msg.bytes, elem->bytes, elem->length);
                    freeRastaByteArray(elem);
                    rfree(elem);
                    app_messages.data_array[i] = msg;
                }

                struct RastaPacket data = createDataMessage(con->remote_id, con->my_id, con->sn_t,
                                                            con->cs_t, cur_timestamp(), con->ts_r,
                                                            app_messages, h->hashing_context);

                struct RastaByteArray packet = rastaModuleToBytes(data, h->hashing_context);

                struct RastaByteArray *to_fifo = rmalloc(sizeof(struct RastaByteArray));
                allocateRastaByteArray(to_fifo, packet.length);
                rmemcpy(to_fifo->bytes, packet.bytes, packet.length);
                if (!fifo_push(con->fifo_retransmission, to_fifo)) {
                    logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA send handler", "discarding packet because retransmission queue is full");
                }

                redundancy_mux_send(h->mux, data);

                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA send handler", "Sent data packet from queue");

                con->sn_t = data.sequence_number + 1;

                // set last message ts
                reschedule_event(&con->send_heartbeat_event);

                con->hb_stopped = 0;

                freeRastaMessageData(&app_messages);
                freeRastaByteArray(&packet);
                freeRastaByteArray(&data.data);

                con->is_sending = 0;
            }
        }
    }
    return 0;
}

void log_main_loop_state(struct rasta_handle *h, event_system *ev_sys, const char *message) {
    int fd_event_count = 0, fd_event_active_count = 0, timed_event_count = 0, timed_event_active_count = 0;
    for (fd_event *ev = ev_sys->fd_events.first; ev; ev = ev->next) {
        fd_event_count++;
        fd_event_active_count += !!ev->enabled;
    }
    for (timed_event *ev = ev_sys->timed_events.first; ev; ev = ev->next) {
        timed_event_count++;
        timed_event_active_count += !!ev->enabled;
    }
    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA EVENT-SYSTEM", "%s | %d/%d fd events and %d/%d timed events active",
               message, fd_event_active_count, fd_event_count, timed_event_active_count, timed_event_count);
}

struct rasta_connection *handle_conreq(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket *receivedPacket) {
    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Received ConnectionRequest from %d", receivedPacket->sender_id);
    // struct rasta_connection* con = rastalist_getConnectionByRemote(&h->connections, receivedPacket->sender_id);
    if (connection == NULL || connection->current_state == RASTA_CONNECTION_CLOSED || connection->current_state == RASTA_CONNECTION_DOWN) {
        // new client
        if (connection == NULL) {
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Prepare new client");
        } else {
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Reset existing client");
        }
        struct rasta_connection new_con;

        sr_init_connection(&new_con, receivedPacket->sender_id, h->info, h->config, h->logger, RASTA_ROLE_SERVER);

        // initialize seq num
        new_con.sn_t = new_con.sn_i = receivedPacket->sequence_number;

        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Using %lu as initial sequence number",
                   (long unsigned int)new_con.sn_t);

        new_con.current_state = RASTA_CONNECTION_DOWN;

        // check received packet (5.5.2)
        if (!sr_check_packet(&new_con, h->logger, h->config, receivedPacket, "RaSTA HANDLE: ConnectionRequest")) {
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Packet is not valid");
            sr_close_connection(&new_con, h->handle, h->mux, h->info, RASTA_DISC_REASON_PROTOCOLERROR, 0);
            return connection;
        }

        // received packet is a ConReq -> check version
        struct RastaConnectionData connectionData = extractRastaConnectionData(receivedPacket);

        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Client has version %s", connectionData.version);

        if (compare_version(RASTA_VERSION, connectionData.version) == 0 ||
            compare_version(RASTA_VERSION, connectionData.version) == -1 ||
            version_accepted(&h->handle->config, connectionData.version)) {

            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Version accepted");

            // same version, or lower version -> client has to decide -> send ConResp

            // set values according to 5.6.2 [3]
            new_con.sn_r = receivedPacket->sequence_number + 1;
            new_con.cs_t = receivedPacket->sequence_number;
            new_con.ts_r = receivedPacket->timestamp;
            new_con.cts_r = receivedPacket->confirmed_timestamp;
            new_con.cs_r = receivedPacket->confirmed_sequence_number;

            // save N_SENDMAX of partner
            new_con.connected_recv_buffer_size = connectionData.send_max;

            new_con.t_i = h->config.t_max;

            unsigned char *version = (unsigned char *)RASTA_VERSION;

            // send ConResp
            struct RastaPacket conresp = createConnectionResponse(new_con.remote_id, new_con.my_id,
                                                                  new_con.sn_t, new_con.cs_t,
                                                                  cur_timestamp(), new_con.cts_r,
                                                                  h->config.send_max,
                                                                  version, h->hashing_context);

            new_con.sn_t = new_con.sn_t + 1;

            new_con.current_state = RASTA_CONNECTION_START;

            // check if the connection was just closed
            if (connection) {
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Update Client %d", receivedPacket->sender_id);
                *connection = new_con;
                fire_on_connection_state_change(sr_create_notification_result(h->handle, connection));
                init_connection_events(h->handle, connection);
            } else {
                struct rasta_connection *memory = h->handle->user_handles->on_connection_start(&new_con);
                if (memory == NULL) {
                    logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA HANDLE: ConnectionRequest", "refused %d", receivedPacket->sender_id);
                    return NULL;
                }
                *memory = new_con;
                add_connection_to_list(h->handle, memory);
                fire_on_connection_state_change(sr_create_notification_result(h->handle, memory));
                logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA HANDLE: ConnectionRequest", "Add new client %d", receivedPacket->sender_id);

                init_connection_events(h->handle, memory);
            }

            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Send Connection Response - waiting for Heartbeat");

            // Send connection response immediately (don't go through packet batching)
            redundancy_mux_send(h->mux, conresp);

            freeRastaByteArray(&conresp.data);
        } else {
            logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA HANDLE: ConnectionRequest", "Version unacceptable - sending DisconnectionRequest");
            sr_close_connection(&new_con, h->handle, h->mux, h->info, RASTA_DISC_REASON_INCOMPATIBLEVERSION, 0);
            return connection;
        }
    } else {
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionRequest", "Connection is in invalid state (%d) send DisconnectionRequest", connection->current_state);
        sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_UNEXPECTEDTYPE, 0);
    }
    return connection;
}

struct rasta_connection *handle_conresp(struct rasta_receive_handle *h, struct rasta_connection *con, struct RastaPacket *receivedPacket) {

    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Received ConnectionResponse from %d", receivedPacket->sender_id);

    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Checking packet..");
    if (!sr_check_packet(con, h->logger, h->config, receivedPacket, "RaSTA HANDLE: ConnectionResponse")) {
        sr_close_connection(con, h->handle, h->mux, h->info, RASTA_DISC_REASON_PROTOCOLERROR, 0);
        return con;
    }

    if (con->current_state == RASTA_CONNECTION_START) {
        if (con->role == RASTA_ROLE_CLIENT) {
            // handle normal conresp
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Current state is in order");

            // correct type of packet received -> version check
            struct RastaConnectionData connectionData = extractRastaConnectionData(receivedPacket);

            // logger_log(&connection->logger, LOG_LEVEL_INFO, "RaSTA open con", "server is running RaSTA version %s", connectionData.version);

            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Client has version %s", connectionData.version);

            if (version_accepted(&h->handle->config, connectionData.version)) {

                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Version accepted");

                // same version or accepted versions -> send hb to complete handshake

                // set values according to 5.6.2 [3]
                con->sn_r = receivedPacket->sequence_number + 1;
                con->cs_t = receivedPacket->sequence_number;
                con->ts_r = receivedPacket->timestamp;
                con->cs_r = receivedPacket->confirmed_sequence_number;

                // printf("RECEIVED CS_PDU=%lu (Type=%d)\n", receivedPacket->sequence_number, receivedPacket->type);

                // update state, ready to send data
                con->current_state = RASTA_CONNECTION_UP;

                // send hb
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Sending heartbeat..");
                sendHeartbeat(h->mux, con, 1);

#ifdef ENABLE_OPAQUE
                if (h->handle->config.kex.mode == KEY_EXCHANGE_MODE_OPAQUE) {
                    send_KexRequest(h->mux, con, h);
                }
#endif

                // fire connection state changed event
                fire_on_connection_state_change(sr_create_notification_result(h->handle, con));
                // fire handshake complete event
                fire_on_handshake_complete(sr_create_notification_result(h->handle, con));

                init_connection_events(h->handle, con);

                // start sending heartbeats
                enable_timed_event(&con->send_heartbeat_event);

                con->hb_locked = 0;

                // save the N_SENDMAX of remote
                con->connected_recv_buffer_size = connectionData.send_max;

                // arm the timeout timer
                enable_timed_event(&con->timeout_event);

            } else {
                // version not accepted -> disconnect
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Version not acceptable - send DisonnectionRequest");
                sr_close_connection(con, h->handle, h->mux, h->info, RASTA_DISC_REASON_INCOMPATIBLEVERSION, 0);
                return con;
            }
        } else {
            // Server don't receive conresp
            sr_close_connection(con, h->handle, h->mux, h->info, RASTA_DISC_REASON_UNEXPECTEDTYPE, 0);

            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Server received ConnectionResponse - send Disconnection Request");
            return con;
        }
    } else if (con->current_state == RASTA_CONNECTION_RETRREQ || con->current_state == RASTA_CONNECTION_RETRRUN || con->current_state == RASTA_CONNECTION_UP) {
        sr_close_connection(con, h->handle, h->mux, h->info, RASTA_DISC_REASON_UNEXPECTEDTYPE, 0);
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: ConnectionResponse", "Received ConnectionResponse in wrong state - semd DisconnectionRequest");
        return con;
    }
    return con;
}

// TODO: Move to handlers
int handle_hb(struct rasta_receive_handle *h, struct rasta_connection *connection, struct RastaPacket *receivedPacket) {
    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "Received heartbeat from %d", receivedPacket->sender_id);

    if (connection->current_state == RASTA_CONNECTION_START) {
        // heartbeat is for connection setup
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "Establish connection");

        // if SN not in Seq -> disconnect and close connection
        if (!sr_sn_in_seq(connection, receivedPacket)) {
            logger_log(h->logger, LOG_LEVEL_INFO, "RaSTA HANDLE: Heartbeat", "Connection HB SN not in Seq");

            if (connection->role == RASTA_ROLE_SERVER) {
                // SN not in Seq
                sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_SEQNERROR, 0);
            } else {
                // Client
                sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_UNEXPECTEDTYPE, 0);
            }
        }

        // if client receives HB in START -> disconnect and close
        if (connection->role == RASTA_ROLE_CLIENT) {
            sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_UNEXPECTEDTYPE, 0);
        }

        if (sr_cts_in_seq(connection, h->config, receivedPacket)) {
            // set values according to 5.6.2 [3]
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "Heartbeat is valid connection successful");
            connection->sn_r = receivedPacket->sequence_number + 1;
            connection->cs_t = receivedPacket->sequence_number;
            connection->cs_r = receivedPacket->confirmed_sequence_number;
            connection->ts_r = receivedPacket->timestamp;

            if (h->handle->config.kex.mode == KEY_EXCHANGE_MODE_NONE) {
                // sequence number correct, ready to receive data
                connection->current_state = RASTA_CONNECTION_UP;
            } else {
                // need to negotiate session key first
                connection->current_state = RASTA_CONNECTION_KEX_REQ;
            }

            connection->hb_locked = 0;

            // fire connection state changed event
            fire_on_connection_state_change(sr_create_notification_result(h->handle, connection));
            // fire handshake complete event
            fire_on_handshake_complete(sr_create_notification_result(h->handle, connection));

            // start sending heartbeats
            enable_timed_event(&connection->send_heartbeat_event);

            // arm the timeout timer
            enable_timed_event(&connection->timeout_event);
            return 0;
        } else {
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "Heartbeat is invalid");

            // sequence number check failed -> disconnect
            sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_PROTOCOLERROR, 0);
            return 0;
        }
    }

    if (sr_sn_in_seq(connection, receivedPacket)) {
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "SN in SEQ");
        // heartbeats also permissible during key exchange phase, since computation could exceed heartbeat interval
        if (connection->current_state == RASTA_CONNECTION_UP || connection->current_state == RASTA_CONNECTION_RETRRUN ||
            connection->current_state == RASTA_CONNECTION_KEX_REQ || connection->current_state == RASTA_CONNECTION_KEX_RESP ||
            connection->current_state == RASTA_CONNECTION_KEX_AUTH) {
            // check cts_in_seq
            if (sr_cts_in_seq(connection, h->config, receivedPacket)) {
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "CTS in SEQ");

                updateTimeoutInterval(receivedPacket->confirmed_timestamp, connection, h->config);
                updateDiagnostic(connection, receivedPacket, h->config, h->handle);

                // set values according to 5.6.2 [3]
                connection->sn_r = receivedPacket->sequence_number + 1;
                connection->cs_t = receivedPacket->sequence_number;
                connection->cs_r = receivedPacket->confirmed_sequence_number;
                connection->ts_r = receivedPacket->timestamp;

                connection->cts_r = receivedPacket->confirmed_timestamp;

                // cs_r updated, remove confirmed messages
                sr_remove_confirmed_messages(h, connection);

                if (connection->current_state == RASTA_CONNECTION_RETRRUN) {
                    connection->current_state = RASTA_CONNECTION_UP;
                    logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "State changed from RetrRun to Up");
                    fire_on_connection_state_change(sr_create_notification_result(h->handle, connection));
                }
            } else {
                logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "CTS not in SEQ - send DisconnectionRequest");
                // close connection
                sr_close_connection(connection, h->handle, h->mux, h->info, RASTA_DISC_REASON_TIMEOUT, 0);
            }
        }
    } else {
        logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "SN not in SEQ");

        if (connection->current_state == RASTA_CONNECTION_UP || connection->current_state == RASTA_CONNECTION_RETRRUN) {
            // ignore message, send RetrReq and goto state RetrReq
            // TODO:send retransmission
            // send_retrreq(con);
            connection->current_state = RASTA_CONNECTION_RETRREQ;
            logger_log(h->logger, LOG_LEVEL_DEBUG, "RaSTA HANDLE: Heartbeat", "Send retransmission");

            // fire connection state changed event
            fire_on_connection_state_change(sr_create_notification_result(h->handle, connection));
        }
    }
    return 0;
}

// TODO: This should be moved into safety_retransmission, and not be called from the outside
// Add rasta_connect
int sr_connect(struct rasta_handle *h, unsigned long id, struct RastaIPData *channels, unsigned channels_length) {
    if (connection_exists(h, id))
        return 0;

    if (redundancy_mux_add_channel(h, &h->mux, id, channels, channels_length) != 0) {
        return 1;
    }

    struct rasta_connection new_con;
    memset(&new_con, 0, sizeof(struct rasta_connection));
    sr_init_connection(&new_con, id, h->config.general, h->config.sending, &h->logger, RASTA_ROLE_CLIENT);
    redundancy_mux_set_config_id(&h->mux, id);

    // initialize seq nums and timestamps
    new_con.sn_t = h->config.initial_sequence_number;

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA CONNECT", "Using %lu as initial sequence number",
               (long unsigned int)new_con.sn_t);

    new_con.cs_t = 0;
    new_con.cts_r = cur_timestamp();
    new_con.t_i = h->config.sending.t_max;

    unsigned char *version = (unsigned char *)RASTA_VERSION;

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA CONNECT", "Local version is %s", version);

    // send ConReq
    struct RastaPacket conreq = createConnectionRequest(new_con.remote_id, new_con.my_id,
                                                        new_con.sn_t, cur_timestamp(),
                                                        h->config.sending.send_max,
                                                        version, &h->hashing_context);
    new_con.sn_i = new_con.sn_t;

    // Send connection request immediately (don't go through packet batching)
    redundancy_mux_send(&h->mux, conreq);

    // increase sequence number
    new_con.sn_t++;

    // update state
    new_con.current_state = RASTA_CONNECTION_START;

    void *memory = h->user_handles->on_connection_start(&new_con);
    if (memory == NULL) {
        logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA CONNECT", "connection refused by user to %d", new_con.remote_id);
        return 1;
    }

    struct rasta_connection *con = memory;
    *con = new_con;
    add_connection_to_list(h, con);

    freeRastaByteArray(&conreq.data);

    // fire connection state changed event
    fire_on_connection_state_change(sr_create_notification_result(h, con));

    init_connection_events(h, con);

    // Wait for connection response

    timed_event handshake_timeout_event;
    init_handshake_timeout_event(&handshake_timeout_event, h->config.sending.t_max);
    enable_timed_event(&handshake_timeout_event);
    add_timed_event(h->ev_sys, &handshake_timeout_event);

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA CONNECT", "awaiting connection response from %d", new_con.remote_id);
    log_main_loop_state(h, h->ev_sys, "event-system started");
    event_system_start(h->ev_sys);

    remove_timed_event(h->ev_sys, &handshake_timeout_event);

    // What happened? Timeout, or user abort, or success?
    if (con->current_state != RASTA_CONNECTION_UP) {
        return 1;
    }

    logger_log(&h->logger, LOG_LEVEL_DEBUG, "RaSTA CONNECT", "handshake completed with %d", new_con.remote_id);

    return 0;
}

// This is the time that packets are deferred for creating multi-packet messages
// See section 5.5.10
#define IO_INTERVAL 10000

int rasta_recv(rasta_lib_configuration_t user_configuration, void *buf, size_t len) {
    struct rasta_handle *h = &user_configuration->h;
    event_system *event_system = &user_configuration->rasta_lib_event_system;

    sr_set_receive_buffer(buf, len);

    timed_event send_event;

    // batch outgoing packets
    memset(&send_event, 0, sizeof(timed_event));
    send_event.callback = data_send_event;
    send_event.interval = IO_INTERVAL * 1000lu;
    send_event.carry_data = h->send_handle;
    enable_timed_event(&send_event);
    add_timed_event(event_system, &send_event);

    log_main_loop_state(h, event_system, "event-system started");
    event_system_start(event_system);

    // Remove all stack entries from linked lists...
    remove_timed_event(event_system, &send_event);

    // if (con->current_state != RASTA_CONNECTION_UP) {
    //     return -1;
    // }

    return sr_get_received_data_len();
}

int rasta_send(rasta_lib_configuration_t user_configuration, uint32_t remote_id, void *buf, size_t len) {
    struct RastaMessageData messageData1;
    allocateRastaMessageData(&messageData1, 1);
    messageData1.data_array[0].bytes = buf;
    messageData1.data_array[0].length = len;

    sr_send(&user_configuration->h, remote_id, messageData1);
    rfree(messageData1.data_array);
    return 0;
}

void rasta_bind(struct rasta_handle *h) {
    redundancy_mux_bind(&h->mux);
}
