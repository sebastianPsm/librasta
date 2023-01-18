#include <rasta/rastahandle.h>

#include <rasta/rmemory.h>
#include <stdlib.h>

struct rasta_notification_result sr_create_notification_result(struct rasta_handle *handle, struct rasta_connection *connection) {
    struct rasta_notification_result r;

    r.handle = handle;
    r.connection = *connection;

    return r;
}

/**
 * the is the function that handles the call of the onConnectionStateChange notification pointer.
 * this runs on a separate thread
 * @param connection the connection that will be used
 * @return unused
 */
void on_constatechange_call(struct rasta_notification_result *result) {
    (*result->handle->notifications.on_connection_state_change)(result);
}

/**
 * fires the onConnectionStateChange event.
 * This implementation will take care if the function pointer is NULL and start a thread to call the notification
 * @param connection the connection that is used
 */
void fire_on_connection_state_change(struct rasta_notification_result result) {
    if (result.handle->notifications.on_connection_state_change == NULL) {
        // notification not set, do nothing
        return;
    }

    on_constatechange_call(&result);
}

void on_receive_call(struct rasta_notification_result *result) {
    (*result->handle->notifications.on_receive)(result);
}

/**
 * fires the onConnectionStateChange event.
 * This implementation will take care if the function pointer is NULL and start a thread to call the notification
 * @param connection the connection that is used
 */
void fire_on_receive(struct rasta_notification_result result) {
    if (result.handle->notifications.on_receive == NULL) {
        // notification not set, do nothing
        return;
    }

    // create container
    struct rasta_notification_result *container = rmalloc(sizeof(struct rasta_notification_result));
    *container = result;

    on_receive_call(&result);
}

void on_discrequest_change_call(struct rasta_disconnect_notification_result *container) {
    struct rasta_disconnect_notification_result *result = (struct rasta_disconnect_notification_result *)container;

    (*result->result.handle->notifications.on_disconnection_request_received)(&result->result, result->reason, result->detail);

    // free container
    rfree(container);
}

/**
 * fires the onConnectionStateChange event.
 * This implementation will take care if the function pointer is NULL and start a thread to call the notification
 * @param connection the connection that is used
 */
void fire_on_discrequest_state_change(struct rasta_notification_result result, struct RastaDisconnectionData data) {

    if (result.handle->notifications.on_disconnection_request_received == NULL) {
        // notification not set, do nothing
        return;
    }

    // create container

    struct rasta_disconnect_notification_result *container = rmalloc(sizeof(struct rasta_disconnect_notification_result));
    container->result = result;
    container->reason = data.reason;
    container->detail = data.details;

    on_discrequest_change_call(container);
}

/**
 * the is the function that handles the call of the onDiagnosticNotification notification pointer.
 * this runs on a separate thread
 * @param connection the connection that will be used
 * @return unused
 */
void on_diagnostic_call(void *container) {
    struct rasta_notification_result *result = (struct rasta_notification_result *)container;

    (*result->handle->notifications.on_diagnostic_notification)(result);

    // free container
    rfree(container);
}

/**
 * fires the onDiagnosticNotification event.
 * This implementation will take care if the function pointer is NULL and start a thread to call the notification
 * @param connection the connection that is used
 */
void fire_on_diagnostic_notification(struct rasta_notification_result result) {

    if (result.handle->notifications.on_diagnostic_notification == NULL) {
        // notification not set, do nothing
        return;
    }

    if (result.connection.received_diagnostic_message_count <= 0) {
        // no diagnostic notification to send
        return;
    }

    // create container
    on_diagnostic_call(&result);
}

void on_handshake_complete_call(struct rasta_notification_result *result) {
    (*result->handle->notifications.on_handshake_complete)(result);
}

void fire_on_handshake_complete(struct rasta_notification_result result) {

    if (result.handle->notifications.on_handshake_complete == NULL) {
        // notification not set, do nothing
        return;
    }

    on_handshake_complete_call(&result);
}

void on_heartbeat_timeout_call(struct rasta_notification_result *container) {
    struct rasta_notification_result *result = (struct rasta_notification_result *)container;

    (*result->handle->notifications.on_heartbeat_timeout)(result);
}

void fire_on_heartbeat_timeout(struct rasta_notification_result result) {

    if (result.handle->notifications.on_heartbeat_timeout == NULL) {
        // notification not set, do nothing
        return;
    }

    on_heartbeat_timeout_call(&result);
}

void rasta_handle_init(struct rasta_handle *h, struct RastaConfigInfo config, struct logger_t *logger) {

    h->config = config;
    h->logger = h->redlogger = *logger;

    // set notification pointers to NULL
    h->notifications.on_receive = NULL;
    h->notifications.on_connection_state_change = NULL;
    h->notifications.on_diagnostic_notification = NULL;
    h->notifications.on_disconnection_request_received = NULL;
    h->notifications.on_redundancy_diagnostic_notification = NULL;

    // init the list
    h->first_con = NULL;
    h->last_con = NULL;

    // init hashing context
    h->hashing_context.hash_length = h->config.sending.md4_type;
    h->hashing_context.algorithm = h->config.sending.sr_hash_algorithm;

    if (h->hashing_context.algorithm == RASTA_ALGO_MD4) {
        // use MD4 IV as key
        rasta_md4_set_key(&h->hashing_context, h->config.sending.md4_a, h->config.sending.md4_b,
                          h->config.sending.md4_c, h->config.sending.md4_d);
    } else {
        // use the sr_hash_key
        allocateRastaByteArray(&h->hashing_context.key, sizeof(unsigned int));

        // convert unsigned in to byte array
        h->hashing_context.key.bytes[0] = (h->config.sending.sr_hash_key >> 24) & 0xFF;
        h->hashing_context.key.bytes[1] = (h->config.sending.sr_hash_key >> 16) & 0xFF;
        h->hashing_context.key.bytes[2] = (h->config.sending.sr_hash_key >> 8) & 0xFF;
        h->hashing_context.key.bytes[3] = (h->config.sending.sr_hash_key) & 0xFF;
    }

    // setup thread data
    h->recv_running = 0;
    h->send_running = 0;
    h->hb_running = 0;

    h->receive_handle = rmalloc(sizeof(struct rasta_receive_handle));
    h->heartbeat_handle = rmalloc(sizeof(struct rasta_heartbeat_handle));
    h->send_handle = rmalloc(sizeof(struct rasta_sending_handle));

    // receive
    h->receive_handle->config = h->config.sending;
    h->receive_handle->info = h->config.general;
    h->receive_handle->handle = h;
    h->receive_handle->running = &h->recv_running;
    h->receive_handle->logger = &h->logger;
    h->receive_handle->mux = &h->mux;
    h->receive_handle->hashing_context = &h->hashing_context;

    // send
    h->send_handle->config = h->config.sending;
    h->send_handle->info = h->config.general;
    h->send_handle->handle = h;
    h->send_handle->running = &h->send_running;
    h->send_handle->logger = &h->logger;
    h->send_handle->mux = &h->mux;
    h->send_handle->hashing_context = &h->hashing_context;

    // heartbeat
    h->heartbeat_handle->config = h->config.sending;
    h->heartbeat_handle->info = h->config.general;
    h->heartbeat_handle->handle = h;
    h->heartbeat_handle->running = &h->hb_running;
    h->heartbeat_handle->logger = &h->logger;
    h->heartbeat_handle->mux = &h->mux;
    h->heartbeat_handle->hashing_context = &h->hashing_context;
}

void add_connection_to_list(struct rasta_handle *h, struct rasta_connection *con) {
    if (h->last_con) {
        con->linkedlist_prev = h->last_con;
        con->linkedlist_next = NULL;
        h->last_con->linkedlist_next = con;
    } else {
        h->first_con = con;
        h->last_con = con;
        con->linkedlist_prev = NULL;
        con->linkedlist_next = NULL;
    }
}

void remove_connection_from_list(struct rasta_handle *h, struct rasta_connection *con) {
    if (h->first_con == con) {
        h->first_con = con->linkedlist_next;
    }
    if (h->last_con == con) {
        h->last_con = con->linkedlist_prev;
    }
    if (con->linkedlist_prev) con->linkedlist_prev->linkedlist_next = con->linkedlist_next;
    if (con->linkedlist_next) con->linkedlist_next->linkedlist_prev = con->linkedlist_prev;
}

int connection_exists(struct rasta_handle *h, unsigned long id) {
    for (struct rasta_connection *con = h->first_con; con; con = con->linkedlist_next) {
        // TODO: Error handling
        if (con->remote_id == id)
            return 1;
    }
    return 0;
}
