#include <arpa/inet.h>
#define IPV4_STR_LEN 16

/**
 * This function will initialise a socket and return its file descriptor, which is used to reference it in later
 * function calls
 * @return the socket's file descriptor
 */
int bsd_create_socket(int family, int type, int protocol_type);

/**
 * Binds a given file descriptor to the given @p port
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 */
void bsd_bind_port(int file_descriptor, uint16_t port);

/**
 * Binds a given file descriptor to the given @p port at the network interface with IPv4 address @p ip
 * @param file_descriptor the is the file descriptor which will be bound to to the @p port.
 * @param port the port the socket will listen on
 * @param ip the IPv4 address of the network interface the socket will listen on.
 */
void bsd_bind_device(int file_descriptor, uint16_t port, char *ip);

/**
 * Receive data on the given @p file descriptor and store it in the given buffer.
 * This function will block until data is received!
 * @param file_descriptor the file descriptor which should be used to receive data
 * @param received_message a buffer where the received data will be written too. Has to be at least \p max_buffer_len long
 * @param max_buffer_len the amount of data which will be received in bytes
 * @param sender information about the sender of the data will be stored here
 * @return the amount of received bytes
 */
size_t bsd_receive(int file_descriptor, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender);

/**
 * Sends a message via the given file descriptor to a @p host and @p port
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message which will be send
 * @param message_len the length of the @p message
 * @param host the host where the message will be send to. This has to be an IPv4 address in the format a.b.c.d
 * @param port the target port on the host
 */
void bsd_send(int file_descriptor, unsigned char *message, size_t message_len, char *host, uint16_t port);

/**
 * Sends a message via the given file descriptor to a host, the address information is stored in the
 * @p receiver struct
 * @param file_descriptor the file descriptor which is used to send the message
 * @param message the message which will be send
 * @param message_len the length of the @p message
 * @param receiver address information about the receiver of the message
 */
void bsd_send_sockaddr(int file_descriptor, unsigned char *message, size_t message_len, struct sockaddr_in receiver);

/**
 * Closes the socket
 * @param file_descriptor the file descriptor which identifies the socket
 */
void bsd_close(int file_descriptor);

/**
 * clears the erros of the socket and prepares for closing
 * @param fd the file descriptor
 * @return the socket state
 */
int getSO_ERROR(int fd);

void sockaddr_to_host(struct sockaddr_in sockaddr, char *host);

struct sockaddr_in host_port_to_sockaddr(const char *host, uint16_t port);
