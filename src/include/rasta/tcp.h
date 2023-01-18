#include <netinet/in.h>
#include <stdint.h>
// TODO: remove udp.h
#include "udp.h"

#define MAX_PENDING_CONNECTIONS 5

/**
 * This function will initialise a tcp socket and return its file descriptor, which is used to reference it in later
 * function calls
 * @param transport_state the tcp socket's tls_transport_state buffer
 * @param tls_config TLS options
 */
void tcp_init(struct rasta_transport_state *transport_state, const struct RastaConfigTLS *tls_config);

/**
 * Binds a given file descriptor to the given @p port
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 */
void tcp_bind(struct rasta_transport_state *transport_state, uint16_t port);

/**
 * Prepare to accept connections on the given @p file_descriptor.
 * @param file_descriptor the file descriptor to accept connections from
 */
void tcp_listen(struct rasta_transport_state *transport_state);

/**
 * Binds a given file descriptor to the given @p port at the network interface with IPv4 address @p ip
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 * @param ip the IPv4 address of the network interface the socket will listen on.
 */
void tcp_bind_device(struct rasta_transport_state *transport_state, uint16_t port, char *ip);

#ifdef ENABLE_TLS
/**
 * Receive data on an ssl connection
 * This function will block until data is received!
 * @param file_descriptor the file descriptor which should be used to receive data
 * @param received_message a buffer where the received data will be written too. Has to be at least \p max_buffer_len long
 * @param max_buffer_len the amount of data which will be received in bytes
 * @param sender information about the sender of the data will be stored here
 * @return the amount of received bytes
 */
ssize_t tls_receive(WOLFSSL *ssl, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender);
#else
/**
 * Receive data on the given @p file descriptor and store it in the given buffer.
 * This function will block until data is received!
 * @param ssl the wolfssl session object
 * @param received_message a buffer where the received data will be written too. Has to be at least \p max_buffer_len long
 * @param max_buffer_len the amount of data which will be received in bytes
 * @param sender information about the sender of the data will be stored here
 * @return the amount of received bytes
 */
size_t tcp_receive(struct rasta_transport_state *transport_state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender);
#endif

/**
 * Await a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 */
int tcp_accept(struct rasta_transport_state *transport_state);

#ifdef ENABLE_TLS
/**
 * Await a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 * @param connectionState the RastaConnectionState accept the ssl parameters
 */
void tcp_accept_tls(struct rasta_transport_state *transport_state, struct rasta_connected_transport_channel_state *connectionState);
#endif

/**
 * Open a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void tcp_connect(struct rasta_transport_state *transport_state, char *host, uint16_t port);

#ifdef ENABLE_TLS
/**
 * Sends a message via tls
 * @param ssl the wolfssl session object
 * @param message the message that which will be send
 * @param message_len the length of the @p message
 */
void tls_send(WOLFSSL *ssl, unsigned char *message, size_t message_len);
#else
/**
 * Sends a message via the given file descriptor to a @p host and @p port
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message that which will be send
 * @param message_len the length of the @p message
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void tcp_send(struct rasta_transport_state *transport_state, unsigned char *message, size_t message_len, char *host, uint16_t port);
#endif

/**
 * Closes the tcp socket
 * @param transport_state the transport state either the filedescriptor (tcp) or the ssl session (tls)
 */
void tcp_close(struct rasta_transport_state *transport_state);

void get_client_addr_from_socket(const struct rasta_transport_state *transport_state, struct sockaddr_in *client_addr, socklen_t *addr_len);
