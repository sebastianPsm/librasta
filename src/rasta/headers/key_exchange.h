//
// Created by erica on 04/07/2022.
//
#pragma once
#ifndef RASTA_KEY_EXCHANGE_H
#define RASTA_KEY_EXCHANGE_H
#include <stdint.h>

#include "logging.h"

#ifdef ENABLE_OPAQUE
#include <opaque.h>
#endif

enum KEY_EXCHANGE_MODE{
    KEY_EXCHANGE_MODE_NONE,
#ifdef ENABLE_OPAQUE
    KEY_EXCHANGE_MODE_OPAQUE
#endif
};

/**
 * Holds state required for key exchange
 */
struct key_exchange_state {
#ifdef ENABLE_OPAQUE
    /**
     * User "registration" record, based on the PSK and the IDs
     */
    uint8_t user_record[OPAQUE_USER_RECORD_LEN];
    /**
     * Holds the PSK and other secret data in the client
     */
    uint8_t *client_secret;
    /**
     * Holds the client public record to be sent to or received by the server
     */
    uint8_t client_public[OPAQUE_USER_SESSION_PUBLIC_LEN];
    /**
     * Certificate response from server
     */
    uint8_t certificate_response[OPAQUE_SERVER_SESSION_LEN];
    /**
     * Common secret session key
     */
    uint8_t session_key[OPAQUE_SHARED_SECRETBYTES];
    /**
     * Data required by server to explicitly authenticate client
     */
    uint8_t user_auth_server[crypto_auth_hmacsha512_BYTES];

    size_t password_length;
#endif
    enum KEY_EXCHANGE_MODE active_mode;
};


/**
 * [SERVER] Prepare a user record from a PSK and the RaSTA IDs
 * @param kex_state Key exchange state
 * @param psk Null-terminated pre-shared key
 * @param my_id server RaSTA ID
 * @param remote_id client RaSTA ID
 * @param logger
 * @return 0 on success
 */
int key_exchange_prepare_from_psk(struct key_exchange_state *kex_state, const char *psk, uint32_t my_id,
                                  uint32_t remote_id, struct logger_t *logger);
/**
 * [CLIENT] Prepare an opaque client request to be sent to the server.
 * @param kex_state Key exchange state
 * @param psk Null-terminated pre-shared key
 * @param logger
 * @return 0 on success
 */
int key_exchange_prepare_credential_request(struct key_exchange_state *kex_state, const char *psk,
                                            struct logger_t *logger);
/**
 * [SERVER] process client connection request and prepare connection response in kex_state
 * @param kex_state Key exchange state
 * @param received_client_public received credential request
 * @param received_client_public_length number of bytes in received request
 * @param my_id server RaSTA ID
 * @param remote_id client RaSTA ID
 * @param initial_sequence_number server ISN
 * @param logger
 * @return 0 on success
 */
int kex_prepare_credential_response(struct key_exchange_state *kex_state,
                                    const uint8_t *received_client_public,
                                    size_t received_client_public_length,
                                    uint32_t my_id, uint32_t remote_id,
                                    uint32_t initial_sequence_number, struct logger_t *logger);
/**
 * [CLIENT] recover credential from key exchange
 * @param kex_state Key exchange state
 * @param received_server_response received credential response
 * @param my_id client RaSTA ID
 * @param remote_id server RaSTA ID
 * @param initial_sequence_number server ISN
 * @param logger
 * @return 0 on success
 */
int kex_recover_credential(struct key_exchange_state *kex_state,
                           const uint8_t *received_server_response,
                           size_t received_server_response_len,
                           uint32_t my_id, uint32_t remote_id,
                           uint32_t initial_sequence_number, struct logger_t *logger);
/**
 * [SERVER] Compares authentication token received from client with authentication token received from server
 * @param kex_state Kex exchange state
 * @param received_user_auth key exchange received from client
 * @param received_user_auth_length number of bytes in key exchange response
 * @param logger
 * @return 0 on success
 */
int kex_authenticate_user(const struct key_exchange_state *kex_state,const uint8_t *received_user_auth, size_t received_user_auth_length, struct logger_t *logger);

#endif //RASTA_KEY_EXCHANGE_H
