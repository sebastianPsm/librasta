#pragma once

#ifdef __cplusplus
extern "C" { // only need to export C interface if
             // used by C++ source code
#endif

#include <stdint.h>

#include "config.h"
#include "fifo.h"
#include "logging.h"
#include "rastacrc.h"
#include "rastadeferqueue.h"

typedef struct rasta_transport_channel rasta_transport_channel;
typedef struct rasta_transport_socket rasta_transport_socket;
struct rasta_receive_handle;
struct rasta_handle;

/**
 * maximum size of messages in the defer queue in bytes
 */
#define MAX_DEFER_QUEUE_MSG_SIZE 1000


/**
 * representation of the state of a redundancy channel as defined in 6.6.4.1
 */
typedef enum {
    /**
     * Redundancy channel is up
     */
    RASTA_RED_UP,

    /**
     * redundancy channel is down
     */
    RASTA_RED_CLOSED
} rasta_redundancy_state;

/**
 * representation of a RaSTA redundancy channel
 */
typedef struct rasta_redundancy_channel {
    /**
     * the RaSTA ID of the remote entity this channel is bound to
     */
    unsigned long associated_id;

    /**
     * the type of checksum that is used for all messages
     */
    struct crc_options checksum_type;

    /**
     * next sequence number to send
     */
    unsigned long seq_tx;

    /**
     * next expected sequence number to be received
     */
    unsigned long seq_rx;

    /**
     * the defer queue
     */
    struct defer_queue defer_q;

    /**
     * used to store all received packets within a diagnose window
     */
    struct defer_queue diagnostics_packet_buffer;

    /**
     * the transport channels of the partner (client) when running in server mode.
     * these are dynamically initialzed when a message from the corresponding channel is received.
     */
    rasta_transport_channel *transport_channels;

    /**
     * the total amount of transport channels
     */
    unsigned int transport_channel_count;

    /**
     * logger used for logging
     */
    struct logger_t logger;

    /**
     * 1 if the redundancy channel is open, 0 if it is closed
     */
    int is_open;

    /**
     * configuration parameters of the redundancy layer
     */
    rasta_config_redundancy configuration_parameters;

    /**
     * Hashing context for en/decoding SR layer PDUs
     */
    rasta_hashing_context_t hashing_context;
} rasta_redundancy_channel;

/**
 * initializes a new RaSTA redundancy channel
 * @param logger the logger that is used to log information
 * @param config the configuration for the redundancy layer
 * @param transport_channel_count the amount of transport channels of this redundancy channel
 * @param id the RaSTA ID that is associated with this redundancy channel
 * @return an initialized redundancy channel
 */
void red_f_init(struct logger_t logger, rasta_config_info config, unsigned int transport_channel_count,
                unsigned long id, rasta_redundancy_channel *channel);

/**
 * the f_receive function of the redundancy layer
 * @param channel the redundancy channel that is used
 * @param packet the packet that has been received over UDP
 * @param channel_id the index of the transport channel, the @p packet has been received
 */
int red_f_receiveData(struct rasta_receive_handle *h, rasta_redundancy_channel *channel, struct RastaRedundancyPacket packet, int channel_id);

/**
 * the f_deferTmo function of the redundancy layer
 * @param channel the redundancy channel that is used
 */
void red_f_deferTmo(struct rasta_receive_handle *h, rasta_redundancy_channel *channel);

/**
 * blocks until the state is closed and all notification threads terminate
 * @param channel the channel that is used
 */
void rasta_red_wait_for_close(rasta_redundancy_channel *channel);

/**
 * adds a (discovered) transport channel to the @p channel
 * @param channel the redundancy channel where the transport channel will be added
 * @param ip the remote IPv4 of the transport channel
 * @param port the remote port of the transport channel
 */
int rasta_red_add_transport_channel(struct rasta_handle *h, rasta_redundancy_channel *channel,
                                     rasta_transport_socket *transport_state,
                                     char *ip, uint16_t port);

/**
 * frees memory for the @p channel
 * @param channel the channel that is freed
 */
void red_f_cleanup(rasta_redundancy_channel *channel);

#ifdef __cplusplus
}
#endif
