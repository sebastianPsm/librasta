#include <stdint.h>
#include <netinet/in.h>
#include "udp.h"

#define MAX_PENDING_CONNECTIONS 5

#ifdef USE_TCP

/**
 * This function will initialise a tcp socket and return its file descriptor, which is used to reference it in later
 * function calls
 * @param state the tcp socket's tls_state buffer
 * @param tls_config TLS options
 */
void tcp_init(struct RastaState *state, const struct RastaConfigTLS *tls_config);

/**
 * Binds a given file descriptor to the given @p port
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 */
void tcp_bind(struct RastaState *state, uint16_t port);

/**
 * Prepare to accept connections on the given @p file_descriptor.
 * @param file_descriptor the file descriptor to accept connections from
 */
void tcp_listen(struct RastaState *state);

/**
 * Binds a given file descriptor to the given @p port at the network interface with IPv4 address @p ip
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 * @param ip the IPv4 address of the network interface the socket will listen on.
 */
void tcp_bind_device(struct RastaState *state, uint16_t port, char * ip);

/**
 * Receive data on the given @p file descriptor and store it in the given buffer.
 * This function will block until data is received!
 * @param file_descriptor the file descriptor which should be used to receive data
 * @param received_message a buffer where the received data will be written too. Has to be at least \p max_buffer_len long
 * @param max_buffer_len the amount of data which will be received in bytes
 * @param sender information about the sender of the data will be stored here
 * @return the amount of received bytes
 */
#ifdef ENABLE_TLS
ssize_t tcp_receive(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender);
#else
size_t tcp_receive(struct RastaState *state, unsigned char* received_message,size_t max_buffer_len, struct sockaddr_in *sender);
#endif
/**
 * Await a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 */
void tcp_accept(struct RastaState *state, struct RastaConnectionState *connectionState);

/**
 * Open a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void tcp_connect(struct RastaState *state,  char *host, uint16_t port);

/**
 * Sends a message via the given file descriptor to a @p host and @p port
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message which will be send
 * @param message_len the length of the @p message
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
#ifdef ENABLE_TLS
void tcp_send(WOLFSSL *ssl, unsigned char *message, size_t message_len);
#else
void tcp_send(struct RastaState *state, unsigned char* message, size_t message_len, char* host, uint16_t port);
#endif

/**
 * Closes the tcp socket
 * @param file_descriptor the file descriptor which identifies the socket
 */
void tcp_close(struct RastaState *state);

void sockaddr_to_host(struct sockaddr_in sockaddr, char* host);

void tcp_init(struct RastaState *state, const struct RastaConfigTLS *tls_config);

void get_client_addr_from_socket(const struct RastaState *state, struct sockaddr_in *client_addr, socklen_t *addr_len);

#endif
