#include <stdint.h>
#include <netinet/in.h>

#define MAX_PENDING_CONNECTIONS 5

/**
 * This function will initialise an tcp socket and return its file descriptor, which is used to reference it in later
 * function calls
 * @return the tcp socket's file descriptor
 */
int tcp_init();

/**
 * Binds a given file descriptor to the given @p port
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 */
void tcp_bind(int file_descriptor, uint16_t port);

/**
 * Prepare to accept connections on the given @p file_descriptor.
 * @param file_descriptor the file descriptor to accept connections from
 */
void tcp_listen(int socket);

/**
 * Binds a given file descriptor to the given @p port at the network interface with IPv4 address @p ip
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 * @param ip the IPv4 address of the network interface the socket will listen on.
 */
void tcp_bind_device(int file_descriptor, uint16_t port, char * ip);

/**
 * Receive data on the given @p file descriptor and store it in the given buffer.
 * This function will block until data is received!
 * @param file_descriptor the file descriptor which should be used to receive data
 * @param received_message a buffer where the received data will be written too. Has to be at least \p max_buffer_len long
 * @param max_buffer_len the amount of data which will be received in bytes
 * @param sender information about the sender of the data will be stored here
 * @return the amount of received bytes
 */
size_t tcp_receive(int file_descriptor, unsigned char* received_message,size_t max_buffer_len, struct sockaddr_in *sender);

/**
 * Await a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 * @param sender address of the connecting peer
 */
int tcp_accept(int file_descriptor, struct sockaddr_in *sender);

/**
 * Open a connection on a @p file_descriptor.
 * When a connection arrives, open a new socket to communicate with it,
 * @param file_descriptor the file descriptor to accept connections from
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void tcp_connect(int file_descriptor,  char *host, uint16_t port);

/**
 * Sends a message via the given file descriptor to a @p host and @p port
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message which will be send
 * @param message_len the length of the @p message
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void tcp_send(int file_descriptor, unsigned char* message, size_t message_len, char* host, uint16_t port);

/**
 * Sends a message via the given file descriptor to a host, the address information is stored in the
 * @p receiver struct
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message which will be send
 * @param message_len the length of the @p message
 * @param receiver address information about the receiver of the message
 */
void tcp_send_sockaddr(int file_descriptor, unsigned char* message, size_t message_len, struct sockaddr_in receiver);

/**
 * Closes the tcp socket
 * @param file_descriptor the file descriptor which identifies the socket
 */
void tcp_close(int file_descriptor);

void sockaddr_to_host(struct sockaddr_in sockaddr, char* host);
