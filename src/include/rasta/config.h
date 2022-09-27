#pragma once

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

#include "logging.h"
#include "rastafactory.h"
#include "key_exchange.h"

#define CONFIG_BUFFER_LENGTH 10000

/**
 * defined in 7.2
 */
struct RastaConfigInfoSending {
    unsigned int t_max;
    unsigned int t_h;
    rasta_checksum_type md4_type;
    MD4_u32plus md4_a;
    MD4_u32plus md4_b;
    MD4_u32plus md4_c;
    MD4_u32plus md4_d;
    unsigned short mwa;
    unsigned short send_max;
    unsigned int max_packet;
    unsigned int diag_window;
    unsigned int sr_hash_key;
    rasta_hash_algorithm sr_hash_algorithm;
};

/**
 * represents an IP and Port
 */
struct RastaIPData {
    char ip[16];
    int port;
};

/**
 * represents a list of IP-Port
 */
struct RastaConfigRedundancyConnections {
    struct RastaIPData *data;
    unsigned int count;
};

/**
 * defined in 7.3
 */
struct RastaConfigInfoRedundancy {
    struct RastaConfigRedundancyConnections connections;
    struct crc_options crc_type;
    unsigned int t_seq;
    int n_diagnose;
    unsigned int n_deferqueue_size;
};

/**
 * defined in 8.1
 */
struct RastaConfigInfoGeneral {
    unsigned long rasta_network;
    unsigned long rasta_id;
};

enum RastaTLSMode
{
    TLS_MODE_DISABLED,
    TLS_MODE_DTLS_1_2,
    TLS_MODE_TLS_1_3
};
// max length of CN in ASN.1
#define MAX_DOMAIN_LENGTH 64

/**
 * Non-standard extension
 */
struct RastaConfigTLS {
    enum RastaTLSMode mode;

    /**
     * Path to CA certificate to use, required for server and client operation
     */
    char ca_cert_path[PATH_MAX];
    /**
    * Path to server certificate to use, required for server and client operation
    */
    char cert_path[PATH_MAX];
    /**
    * Path to server private key to use, required for server operation
    */
    char key_path[PATH_MAX];
    /**
     * Domain / common name to validate TLS certificates against (as client)
     */
    char tls_hostname[MAX_DOMAIN_LENGTH];
    /**
     * path to peer certificate for certificate pinning. Optional.
     */
    char peer_tls_cert_path[PATH_MAX];
};


/**
 * stores all presets after load
 */
struct RastaConfigInfo {
    uint32_t initial_sequence_number;

    size_t accepted_version_count;
    char (*accepted_versions)[4];

    /**
     * all values for the sending part
     */
    struct RastaConfigInfoSending sending;
    /**
     * all values for the redundancy part
     */
    struct RastaConfigInfoRedundancy redundancy;
    /**
     * includes rastanetwork, receiver and sender id
     * values are 0 if not set in config
     */
    struct RastaConfigInfoGeneral general;
    /**
     * Configuration for TLS / dTLS setup.
     * Must set mode, and for mode != TLS_MODE_DISABLED, paths to certificate and keys must be set as required
     */
    struct RastaConfigTLS tls;
    /**
     * Configuration for Key Exchange.
     * Must set mode, and for mode != KEX_EXCHANGE_MODE_NONE also psk.
     */
    struct RastaConfigKex kex;
};

#ifdef __cplusplus
}
#endif
