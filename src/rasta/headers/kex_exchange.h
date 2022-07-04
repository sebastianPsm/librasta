//
// Created by erica on 04/07/2022.
//
#pragma once
#ifndef RASTA_KEX_EXCHANGE_H
#define RASTA_KEX_EXCHANGE_H
#include <stdint.h>
#include "rastahandle.h"
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
 * @param my_id server RaSTA ID
 * @param remote_id client RaSTA ID
 * @param initial_sequence_number server ISN
 * @param logger
 * @return 0 on success
 */
int kex_prepare_credential_response(struct key_exchange_state *kex_state,
                                    const uint8_t *received_client_public,
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
                           uint32_t my_id, uint32_t remote_id,
                           uint32_t initial_sequence_number, struct logger_t *logger);
/**
 * Compares authentication token received from client with authentication token received from server
 * @param kex_state Kex exchange state
 * @param received_user_auth key exchange received from client
 * @param logger
 * @return 0 on success
 */
int kex_authenticate_user(const struct key_exchange_state *kex_state,const uint8_t *received_user_auth, struct logger_t *logger);

#endif //RASTA_KEX_EXCHANGE_H
