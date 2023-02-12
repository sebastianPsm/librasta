#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rasta/fifo.h>
#include <rasta/logging.h>
#include <rasta/rasta_lib.h>
#include <rasta/rmemory.h>

#include "configfile.h"

#define CONFIG_PATH_S "rasta_server_local.cfg"
#define CONFIG_PATH_C "rasta_client_local.cfg"

#define ID_R 0x61
#define ID_S 0x62

#define BUF_SIZE 500

void printHelpAndExit(void) {
    printf("Invalid Arguments!\n use 'r' to start in receiver mode and 's' to start in sender mode.\n");
    exit(1);
}

void addRastaString(struct RastaMessageData *data, int pos, char *str) {
    int size = strlen(str) + 1;

    struct RastaByteArray msg;
    allocateRastaByteArray(&msg, size);
    rmemcpy(msg.bytes, str, size);

    data->data_array[pos] = msg;
}

struct connect_event_data {
    rasta_lib_configuration_t rc;
    uint32_t remote_id;
};

int send_input_data(void *carry_data) {
    struct connect_event_data *data = carry_data;
    char buf[BUF_SIZE];
    int c;

    for (;;) {
        size_t read_len = 0;
        while (read_len < BUF_SIZE) {
            c = getchar();

            if (c == EOF) {
                if (read_len > 0) {
                    rasta_send(data->rc, data->remote_id, buf, read_len);
                }
                // TODO: Disconnect
                // sr_cleanup(&data->rc->h);
                return 1;
            }

            buf[read_len++] = c;

            if (c == '\n') {
                rasta_send(data->rc, data->remote_id, buf, read_len);
                return 0;
            }
        }
        rasta_send(data->rc, data->remote_id, buf, read_len);
    }
}

void *on_con_start(rasta_lib_connection_t connection) {
    (void)connection;
    return malloc(sizeof(rasta_lib_connection_t));
}

void on_con_end(rasta_lib_connection_t connection, void *memory) {
    (void)connection;
    free(memory);
}

int main(int argc, char *argv[]) {

    if (argc != 2) printHelpAndExit();

    rasta_lib_configuration_t rc = {0};

    struct RastaIPData toServer[2];

    strcpy(toServer[0].ip, "127.0.0.1");
    strcpy(toServer[1].ip, "127.0.0.1");
    toServer[0].port = 8888;
    toServer[1].port = 8889;

    fd_event input_available_event;
    struct connect_event_data input_available_event_data;
    // TODO: Terrible API
    input_available_event_data.rc[0] = rc[0];

    input_available_event.callback = send_input_data;
    input_available_event.carry_data = &input_available_event_data;
    input_available_event.fd = STDIN_FILENO;

    char buf[BUF_SIZE];

    if (strcmp(argv[1], "r") == 0) {
        printf("->   R (ID = 0x%lX)\n", (unsigned long)ID_R);
        struct RastaConfigInfo config;
        struct logger_t logger;
        load_configfile(&config, &logger, CONFIG_PATH_S);
        rasta_lib_init_configuration(rc, &config, &logger);
        rc->h.user_handles->on_connection_start = on_con_start;
        rc->h.user_handles->on_disconnect = on_con_end;
        input_available_event_data.remote_id = ID_S;

        rasta_bind(&rc->h);

        sr_listen(&rc->h);

        enable_fd_event(&input_available_event);
        add_fd_event(&rc->rasta_lib_event_system, &input_available_event, EV_READABLE);

        ssize_t recv_len;
        while ((recv_len = rasta_recv(rc, buf, BUF_SIZE)) > 0) {
            // write to stdout
            write(STDOUT_FILENO, buf, recv_len);
        }
    } else if (strcmp(argv[1], "s") == 0) {
        printf("->   S (ID = 0x%lX)\n", (unsigned long)ID_S);
        struct RastaConfigInfo config;
        struct logger_t logger;
        load_configfile(&config, &logger, CONFIG_PATH_C);
        rasta_lib_init_configuration(rc, &config, &logger);
        rc->h.user_handles->on_connection_start = on_con_start;
        rc->h.user_handles->on_disconnect = on_con_end;
        input_available_event_data.remote_id = ID_R;

        rasta_bind(&rc->h);

        if (sr_connect(&rc->h, ID_R, toServer, 2) != 0) {
            printf("->   Failed to connect any channel.\n");
            return 1;
        };

        enable_fd_event(&input_available_event);
        add_fd_event(&rc->rasta_lib_event_system, &input_available_event, EV_READABLE);

        ssize_t recv_len;
        while ((recv_len = rasta_recv(rc, buf, BUF_SIZE)) > 0) {
            write(STDOUT_FILENO, buf, recv_len);
        }
    }

    sr_cleanup(&rc->h);
    return 0;
}
