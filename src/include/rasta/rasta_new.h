#pragma once

#ifdef __cplusplus
extern "C" { // only need to export C interface if
             // used by C++ source code
#endif

// TODO: check
//#include <errno.h>
#include "event_system.h"
#include "rastahandle.h"

/**
 * size of ring buffer where data is hold for retransmissions
 */
#define MAX_QUEUE_SIZE 10 // TODO: maybe in config file

/**
 * the maximum length of application messages in the data of a RaSTA packet.
 * Length of a SCI PDU is max. 44 bytes
 */
#define MAX_APP_MSG_LEN 60

/**
 * maximum length of a RaSTA packet (16 byte MD4 + 5 * 44 bytes of app messages)
 */
#define MAX_PACKET_LEN 264

/**
 * the RaSTA version that is implemented
 */
#define RASTA_VERSION "0303"

#define DIAGNOSTIC_INTERVAL_SIZE 500

#define NS_PER_SEC 1000000000
#define MS_PER_S 1000
#define NS_PER_MS 1000000
/**
 * Reasons for DiscReq as specified in 5.4.6
 */
typedef enum {
    /**
     * Disconnection because of user request
     */
    RASTA_DISC_REASON_USERREQUEST = 0,
    /**
     * Disconnection because of receiving an unexpected type of packet
     */
    RASTA_DISC_REASON_UNEXPECTEDTYPE = 2,
    /**
     * Disconnection because of an error in the sequence number check
     */
    RASTA_DISC_REASON_SEQNERROR = 3,
    /**
     * Disconnection because of a timeout
     */
    RASTA_DISC_REASON_TIMEOUT = 4,
    /**
     * Disconnection because of the call of the service was not allowed
     */
    RASTA_DISC_REASON_SERVICENOTALLOWED = 5,
    /**
     * Disconnection because of the version was not accepted
     */
    RASTA_DISC_REASON_INCOMPATIBLEVERSION = 6,
    /**
     * Disconnection because retransmission failed
     */
    RASTA_DISC_REASON_RETRFAILED = 7,
    /**
     * Disconnection because an error in the protocol flow
     */
    RASTA_DISC_REASON_PROTOCOLERROR = 8
} rasta_disconnect_reason;

typedef struct {
    unsigned long id;
    struct RastaByteArray appMessage;
} rastaApplicationMessage;

/**
 * initializes the rasta handle and starts all threads
 * configuration is loaded from file
 * @param handle
 * @param config_file_path
 * @param listenports
 * @param port_count
 */
void sr_init_handle(struct rasta_handle *handle, struct RastaConfigInfo config, struct logger_t *logger);

void sr_listen(struct rasta_handle *h);

/**
 * connects to another rasta instance
 * @param handle
 * @param id
 */
void sr_connect(struct rasta_handle *handle, unsigned long id, struct RastaIPData *channels);

/**
 * send data to another instance
 * @param h
 * @param remote_id
 * @param app_messages
 */
void sr_send(struct rasta_handle *h, unsigned long remote_id, struct RastaMessageData app_messages);

/**
 * get data from message buffer
 * this is used in the onReceive Event to get the received message
 * @param h
 * @param connection
 * @return the applicationmessage, where id is the sender rasta id and appMessage is the received data
 */
rastaApplicationMessage sr_get_received_data(struct rasta_handle *h, struct rasta_connection *connection);

/**
 * closes the connection to the connection
 * @param h
 * @param con
 */
void sr_disconnect(struct rasta_handle *h, struct rasta_connection *con);

/**
 * used to end all threads an free assigned ressources
 * always use this when a programm terminates otherwise it may not start again
 * @param h
 */
void sr_cleanup(struct rasta_handle *h);

void sr_begin(struct rasta_handle *h, event_system *event_system, int wait_for_handshake, int listen);

#ifdef __cplusplus
}
#endif
