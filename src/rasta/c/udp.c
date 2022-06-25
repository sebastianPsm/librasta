#include "udp.h"
#include <stdio.h>
#include <string.h> //memset
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "rmemory.h"

#ifdef ENABLE_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif


struct sockaddr_in host_port_to_sockaddr(const char *host, uint16_t port) {
    struct sockaddr_in receiver;

    rmemset((char *) &receiver, 0, sizeof(receiver));
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons(port);

    // convert host string to usable format
    if (inet_aton(host, &receiver.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
    return receiver;
}

/**
 * clears the erros of the socket and prepares for closing
 * @param fd the file descriptor
 * @return the socket tls_state
 */
int getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        exit(1);
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}

#define MAX_WARNING_LENGTH_BYTES 128

static void handle_port_unavailable(const uint16_t port) {
    const char *warning_format = "could not bind the socket to port %d";
    char warning_mbuf[MAX_WARNING_LENGTH_BYTES + 1];
    snprintf(warning_mbuf,MAX_WARNING_LENGTH_BYTES,warning_format,port);

    // bind failed
    perror("warning_mbuf");
    exit(1);
}

#ifdef ENABLE_TLS

static void wolfssl_initialize_if_necessary(){
    static bool wolfssl_initialized = false;
    if(!wolfssl_initialized){
        wolfssl_initialized = true;
        wolfSSL_Init();
    }
}

static void wolfssl_start_dtls_server(struct RastaUDPState *state, const struct RastaConfigTLS *tls_config){
    wolfssl_initialize_if_necessary();
    state->ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    if(!state->ctx){
        fprintf(stderr,"Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if(!tls_config->ca_cert_path[0] || !tls_config->cert_path[0] || !tls_config->key_path[0]){
        fprintf(stderr,"CA certificate path, server certificate path or server private key path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(state->ctx,tls_config->ca_cert_path,0) !=
        SSL_SUCCESS) {
        fprintf(stderr, "Error loading CA certificate file %s.\n", tls_config->ca_cert_path);
        exit(1);
    }
    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(state->ctx, tls_config->cert_path, SSL_FILETYPE_PEM) !=
        SSL_SUCCESS) {
        printf("Error loading server certificate file %s as PEM file.\n", tls_config->cert_path);
        exit(1);
    }
    /* Load server Keys */
    if (wolfSSL_CTX_use_PrivateKey_file(state->ctx, tls_config->key_path,
                                        SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Error loading server private key file %s as PEM file.\n", tls_config->key_path);
        exit(1);
    }
    state->ssl = wolfSSL_new(state->ctx);
    if(!state->ssl){
        fprintf(stderr, "Error allocating WolfSSL object.\n");
        exit(1);
    }
    wolfSSL_set_fd(state->ssl,state->file_descriptor);
    state->tls_state = RASTA_TLS_CONNECTION_READY;
    state->tls_config = tls_config;
}

static void wolfssl_start_dtls_client(struct RastaUDPState *state, const struct RastaConfigTLS *tls_config){
    wolfssl_initialize_if_necessary();
    state->ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    if(!state->ctx){
        fprintf(stderr,"Could not allocate WolfSSL context!\n");
        exit(1);
    }

    if(!tls_config->ca_cert_path[0]){
        fprintf(stderr,"CA certificate path missing!\n");
        exit(1);
    }

    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(state->ctx,tls_config->ca_cert_path,0) !=
        SSL_SUCCESS) {
        fprintf(stderr, "Error loading CA certificate file %s.\n", tls_config->ca_cert_path);
        exit(1);
    }
    state->ssl = wolfSSL_new(state->ctx);
    if(!state->ssl){
        fprintf(stderr, "Error allocating WolfSSL object.\n");
        exit(1);
    }
    wolfSSL_set_fd(state->ssl,state->file_descriptor);
    state->tls_state = RASTA_TLS_CONNECTION_READY;
}

static size_t wolfssl_receive_dtls(struct RastaUDPState * state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender){
    int receive_len;
    if(state->tls_state == RASTA_TLS_CONNECTION_READY){
        if (wolfSSL_accept(state->ssl) != SSL_SUCCESS) {

            int e = wolfSSL_get_error(state->ssl, 0);

            fprintf(stderr,"WolfSSL could not accept connection: error = %s\n", wolfSSL_ERR_reason_error_string(e));
            exit(1);
        }
    }
    if((receive_len = wolfSSL_read(state->ssl,received_message,(int)max_buffer_len) > 0)){
        int peer_error = wolfSSL_dtls_get_peer(state->ssl,sender,(unsigned int *) sizeof(struct sockaddr_in));
        if(peer_error != SSL_SUCCESS){
            fprintf(stderr, "Could not get peer from WolfSSL: %d\n",peer_error);
            exit(1);
        }
        return receive_len;
    }
    if(receive_len < 0){
        int readErr = wolfSSL_get_error(state->ssl, 0);
        if(readErr != SSL_ERROR_WANT_READ) {
            fprintf(stderr, "WolfSSL decryption failed: %s.\n", wolfSSL_ERR_reason_error_string(readErr));
            exit(1);
        }
    }
    return 0;
}

static void wolfssl_send_tls(struct RastaUDPState * state, unsigned char *message, size_t message_len, struct sockaddr_in *receiver, const struct RastaConfigTLS *tls_config){
    if(state->tls_state != RASTA_TLS_CONNECTION_ESTABLISHED){
        wolfssl_start_dtls_client(state,tls_config);
        wolfSSL_dtls_set_peer(state->ssl, receiver, sizeof(*receiver));
        /* Set the file descriptor for ssl and connect with ssl variable */
        wolfSSL_set_fd(state->ssl, state->file_descriptor);
        if (wolfSSL_connect(state->ssl) != SSL_SUCCESS) {
            int connect_error = wolfSSL_get_error(state->ssl, 0);
            fprintf(stderr,"WolfSSL connect error: %s\n", wolfSSL_ERR_reason_error_string(connect_error));
            exit(1);
        }
        state->tls_state = RASTA_TLS_CONNECTION_ESTABLISHED;
    }

    if(wolfSSL_write(state->ssl,message,(int) message_len) < 0){
        fprintf(stderr, "WolfSSL write error!");
        exit(1);
    }

}

static void wolfssl_cleanup(struct RastaUDPState *state){
    state->tls_state = RASTA_TLS_CONNECTION_CLOSED;
    wolfSSL_set_fd(state->ssl,0);
    wolfSSL_shutdown(state->ssl);
    wolfSSL_free(state->ssl);
    wolfSSL_CTX_free(state->ctx);
}

#endif

static void handle_tls_mode(struct RastaUDPState *state) {
    const struct RastaConfigTLS *tls_config = state->tls_config;
    switch(tls_config->mode){
        case TLS_MODE_DISABLED:
            state->activeMode = TLS_MODE_DISABLED;
            break;
#ifdef ENABLE_TLS
        case TLS_MODE_DTLS_1_2:
            state->activeMode = TLS_MODE_DTLS_1_2;
            wolfssl_start_dtls_server(state,tls_config);
            break;
#endif
        default:
            fprintf(stderr,"Unknown or unsupported TLS mode: %u",tls_config->mode);
            exit(1);
    }
}

void udp_bind(struct RastaUDPState * state, uint16_t port) {
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *) &local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    // bind socket to port
    if( bind(state->file_descriptor , (struct sockaddr*)&local, sizeof(local) ) == -1)
    {
        handle_port_unavailable(port);
    }
    handle_tls_mode(state);
}

void udp_bind_device(struct RastaUDPState * state, uint16_t port, char * ip) {
    struct sockaddr_in local;

    // set struct to 0s
    rmemset((char *) &local, 0, sizeof(local));

    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = inet_addr(ip);

    // bind socket to port
    if( bind(state->file_descriptor , (struct sockaddr*)&local, sizeof(struct sockaddr_in) ) == -1)
    {
        // bind failed
        handle_port_unavailable(port);
        exit(1);
    }
    handle_tls_mode(state);
}

void udp_close(struct RastaUDPState * state) {
    int file_descriptor = state-> file_descriptor;
    if (file_descriptor >= 0) {

#ifdef ENABLE_TLS
        if(state->activeMode != TLS_MODE_DISABLED){
            wolfssl_cleanup(state);
        }
#endif

        getSO_ERROR(file_descriptor); // first clear any errors, which can cause close to fail
        if (shutdown(file_descriptor, SHUT_RDWR) < 0) // secondly, terminate the 'reliable' delivery
            if (errno != ENOTCONN && errno != EINVAL){ // SGI causes EINVAL
                perror("shutdown");
                exit(1);
            }
        if (close(file_descriptor) < 0) // finally call close()
        {
            perror("close");
            exit(1);
        }
    }
}

size_t udp_receive(struct RastaUDPState * state, unsigned char *received_message, size_t max_buffer_len, struct sockaddr_in *sender) {
    if(state->activeMode == TLS_MODE_DISABLED){
        ssize_t recv_len;
        struct sockaddr_in empty_sockaddr_in;
        socklen_t sender_len = sizeof(empty_sockaddr_in);

        // wait for incoming data
        if ((recv_len = recvfrom(state->file_descriptor, received_message, max_buffer_len, 0, (struct sockaddr *) sender, &sender_len)) == -1)
        {
            perror("an error occured while trying to receive data");
            exit(1);
        }

        return (size_t) recv_len;
    }
#ifdef ENABLE_TLS
    else{
        return wolfssl_receive_dtls(state,received_message,max_buffer_len,sender);
    }
#endif
    return 0;
}

void udp_send(struct RastaUDPState * state, unsigned char *message, size_t message_len, char *host, uint16_t port) {
    struct sockaddr_in receiver = host_port_to_sockaddr(host, port);
    if(state->activeMode == TLS_MODE_DISABLED) {

        // send the message using the other send function
        udp_send_sockaddr(state, message, message_len, receiver);
    }
#ifdef ENABLE_TLS
    else{
        wolfssl_send_tls(state, message, message_len, &receiver,state->tls_config);
    }
#endif
}

void udp_send_sockaddr(struct RastaUDPState * state, unsigned char *message, size_t message_len, struct sockaddr_in receiver)
        {
    if(state->activeMode == TLS_MODE_DISABLED) {
        if (sendto(state->file_descriptor, message, message_len, 0, (struct sockaddr *) &receiver, sizeof(receiver)) ==
            -1) {
            perror("failed to send data");
            exit(1);
        }
    }
#ifdef ENABLE_TLS
    else{
        const struct RastaConfigTLS *tls_config = state->tls_config;
        state->tls_config = tls_config;
        wolfssl_send_tls(state, message, message_len, &receiver,tls_config);
    }
#endif
}

void udp_init(struct RastaUDPState *state,const struct RastaConfigTLS *tls_config) {
    // the file descriptor of the socket
    int file_desc;

    state->tls_config = tls_config;

    // create a udp socket
    if ((file_desc=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        // creation failed, exit
        perror("The udp socket could not be initialized");
        exit(1);
    }
    state->file_descriptor = file_desc;
}

void sockaddr_to_host(struct sockaddr_in sockaddr, char* host){
    inet_ntop(AF_INET, &(sockaddr.sin_addr), host, IPV4_STR_LEN);
}




