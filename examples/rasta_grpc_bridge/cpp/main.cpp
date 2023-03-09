#include <chrono>
#include <condition_variable>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include <rasta/rasta_lib.h>
#include <rasta/rasta.h>
#include <rasta/rmemory.h>

#include "configfile.h"

#include <rasta.grpc.pb.h>
#include <rasta.pb.h>

using namespace std::chrono_literals;

static std::mutex s_busy;

#define BUF_SIZE 500

// Client
static std::unique_ptr<grpc::ClientContext> s_currentContext;
static std::unique_ptr<grpc::ClientReaderWriter<sci::SciPacket, sci::SciPacket>> s_currentStream;

// Server
static grpc::ServerReaderWriter<sci::SciPacket, sci::SciPacket> *s_currentServerStream;
static grpc::ServerContext *s_currentServerContext;

void *on_con_start(rasta_lib_connection_t connection) {
    (void)connection;
    return malloc(sizeof(rasta_lib_connection_t));
}

void on_con_end(rasta_lib_connection_t connection, void *memory) {
    (void)connection;
    free(memory);
}

// struct RastaChannel {
//     unsigned long remote_id;
//     // The size of subchannels implicitly equals the number of local listen endpoints
//     RastaIPData *subchannels;
// };

static uint32_t s_remote_id = 0;
struct rasta_connection *s_connection = NULL;

static int s_terminator_fd;
static int s_data_fd;

static std::mutex s_fifo_mutex;
static fifo_t *s_message_fifo;

void processRasta(std::string config_path,
                  std::string rasta_channel1_address, std::string rasta_channel1_port,
                  std::string rasta_channel2_address, std::string rasta_channel2_port,
                  std::string rasta_local_id, std::string rasta_target_id,
                  std::function<std::thread()> run_thread) {

    unsigned long local_id = std::stoul(rasta_local_id);
    s_remote_id = std::stoul(rasta_target_id);

    // Channels
    struct RastaIPData toServer[2];
    strcpy(toServer[0].ip, rasta_channel1_address.c_str());
    toServer[0].port = std::stoi(rasta_channel1_port);
    strcpy(toServer[1].ip, rasta_channel2_address.c_str());
    toServer[1].port = std::stoi(rasta_channel2_port);

    static rasta_lib_configuration_t s_rc;
    memset(&s_rc, 0, sizeof(rasta_lib_configuration_t));
    rasta_config_info config;
    struct logger_t logger;
    load_configfile(&config, &logger, config_path.c_str());
    rasta_lib_init_configuration(s_rc, &config, &logger);
    s_rc->h.user_handles->on_connection_start = on_con_start;
    s_rc->h.user_handles->on_disconnect = on_con_end;

    rasta_bind(&s_rc->h);

    bool server = local_id > s_remote_id;
    if (server) {
        sr_listen(&s_rc->h);
    }

    while (true) {
        if (server) {
            s_connection = rasta_accept(s_rc);
        } else {
            s_connection = sr_connect(&s_rc->h, local_id, toServer, 2);
        }
        if (s_connection) {
            s_message_fifo = fifo_init(128);

            // Data event
            s_data_fd = eventfd(0, 0);
            fd_event data_event;
            memset(&data_event, 0, sizeof(fd_event));
            data_event.callback = [](void *) {
                RastaByteArray *msg = nullptr;

                {
                    std::lock_guard<std::mutex> guard(s_fifo_mutex);
                    msg = reinterpret_cast<RastaByteArray *>(fifo_pop(s_message_fifo));
                }

                if (msg != nullptr) {
                    rasta_send(s_rc, s_connection,  msg->bytes, msg->length);

                    freeRastaByteArray(msg);
                }

                return 0;
            };
            data_event.carry_data = &s_rc->h;
            data_event.fd = s_data_fd;
            enable_fd_event(&data_event);
            add_fd_event(&s_rc->rasta_lib_event_system, &data_event, EV_READABLE);

            // Terminator event
            s_terminator_fd = eventfd(0, 0);
            fd_event terminator_event;
            memset(&terminator_event, 0, sizeof(fd_event));
            terminator_event.callback = [](void *carry) {
                rasta_handle *h = reinterpret_cast<rasta_handle *>(carry);
                struct rasta_connection *existing_connection = NULL;
                for (struct rasta_connection *con = h->first_con; con; con = con->linkedlist_next) {
                    if (con->remote_id == s_remote_id) {
                        existing_connection = con;
                        break;
                    }
                }
                if (existing_connection != NULL) {
                    sr_disconnect(h, existing_connection);
                }
                return 1;
            };
            terminator_event.carry_data = &s_rc->h;
            terminator_event.fd = s_terminator_fd;
            enable_fd_event(&terminator_event);
            add_fd_event(&s_rc->rasta_lib_event_system, &terminator_event, EV_READABLE);

            // Forward gRPC messages to rasta
            auto forwarderThread = run_thread();

            char buf[BUF_SIZE];
            int recvlen;
            while ((recvlen = rasta_recv(s_rc, s_connection, buf, BUF_SIZE)) > 0) {
                static std::mutex s_busy_writing;
                std::lock_guard<std::mutex> guard(s_busy_writing);

                std::lock_guard<std::mutex> streamGuard(s_busy);
                if (s_currentStream != nullptr) {
                    logger_log(&s_rc->h.logger, LOG_LEVEL_DEBUG, (char *)"RaSTA retrieve", (char *)"forwarding packet to grpc");
                    sci::SciPacket outPacket;
                    outPacket.set_message(buf, recvlen);
                    s_currentStream->Write(outPacket);
                } else if (s_currentServerStream != nullptr) {
                    logger_log(&s_rc->h.logger, LOG_LEVEL_DEBUG, (char *)"RaSTA retrieve", (char *)"forwarding packet to grpc");
                    sci::SciPacket outPacket;
                    outPacket.set_message(buf, recvlen);
                    s_currentServerStream->Write(outPacket);
                } else {
                    logger_log(&s_rc->h.logger, LOG_LEVEL_ERROR, (char *)"RaSTA retrieve", (char *)"discarding packet.");
                }
            }

            {
                std::lock_guard<std::mutex> guard(s_busy);
                if (s_currentContext) {
                    s_currentContext->TryCancel();
                } else if (s_currentServerContext) {
                    s_currentServerContext->TryCancel();
                }
            }

            forwarderThread.join();

            remove_fd_event(&s_rc->rasta_lib_event_system, &data_event);
            remove_fd_event(&s_rc->rasta_lib_event_system, &terminator_event);

            close(s_data_fd);
            close(s_terminator_fd);

            fifo_destroy(&s_message_fifo);
        }

        // Give the remote the chance to notice the possibly broken connection
        sleep(1);
    }

    sr_cleanup(&s_rc->h);
}

class RastaService final : public sci::Rasta::Service {
  public:
    RastaService(std::string config,
                 std::string rasta_channel1_address, std::string rasta_channel1_port,
                 std::string rasta_channel2_address, std::string rasta_channel2_port,
                 std::string rasta_local_id, std::string rasta_target_id)
        : _config(config), _rasta_channel1_address(rasta_channel1_address), _rasta_channel1_port(rasta_channel1_port), _rasta_channel2_address(rasta_channel2_address), _rasta_channel2_port(rasta_channel2_port), _rasta_local_id(rasta_local_id), _rasta_target_id(rasta_target_id) {}

    grpc::Status Stream(grpc::ServerContext *context, grpc::ServerReaderWriter<sci::SciPacket, sci::SciPacket> *stream) override {
        {
            std::lock_guard<std::mutex> guard(s_busy);
            s_currentServerContext = context;
            s_currentServerStream = stream;
        }

        auto forwardGrpc = [&]() {
            return std::thread([&]() {
                sci::SciPacket message;
                while (s_currentServerStream->Read(&message)) {
                    printf("Forwarding gRPC message...\n");
                    struct RastaByteArray *msg = reinterpret_cast<RastaByteArray *>(rmalloc(sizeof(struct RastaByteArray)));
                    allocateRastaByteArray(msg, message.message().size());
                    rmemcpy(msg->bytes, message.message().c_str(), message.message().size());

                    {
                        std::lock_guard<std::mutex> guard(s_fifo_mutex);
                        fifo_push(s_message_fifo, msg);
                    }

                    uint64_t notify_data = 1;
                    uint64_t ignore = write(s_data_fd, &notify_data, sizeof(uint64_t));
                    (void)ignore;
                }

                uint64_t terminate = 1;
                uint64_t ignore = write(s_terminator_fd, &terminate, sizeof(uint64_t));
                (void)ignore;
            });
        };

        processRasta(_config, _rasta_channel1_address, _rasta_channel1_port, _rasta_channel2_address, _rasta_channel2_port, _rasta_local_id, _rasta_target_id, forwardGrpc);

        {
            std::lock_guard<std::mutex> guard(s_busy);
            s_currentServerContext = nullptr;
            s_currentServerStream = nullptr;
        }

        return grpc::Status::OK;
    }

  protected:
    std::string _config;
    std::string _rasta_channel1_address;
    std::string _rasta_channel1_port;
    std::string _rasta_channel2_address;
    std::string _rasta_channel2_port;
    std::string _rasta_local_id;
    std::string _rasta_target_id;
};

int main(int argc, char *argv[]) {
    if (argc < 9) {
        std::cout << "Usage: " << argv[0] << " <config_file> <listen_address> <target_host_ch0> <target_port_ch0> <target_host_ch1> <target_port_ch1> <local_rasta_id> <local_remote_id> <?grpc_target_address>" << std::endl;
        return 1;
    }

    std::string config(argv[1]);

    struct stat buffer;
    if (stat(config.c_str(), &buffer) < 0) {
        std::cerr << "Could not open \"" << config << "\"." << std::endl;
        return 1;
    }

    std::string server_address(argv[2]);
    std::string rasta_channel1_address(argv[3]);
    std::string rasta_channel1_port(argv[4]);
    std::string rasta_channel2_address(argv[5]);
    std::string rasta_channel2_port(argv[6]);
    std::string rasta_local_id(argv[7]);
    std::string rasta_target_id(argv[8]);
    std::string grpc_server_address;
    if (argc >= 10) {
        grpc_server_address = std::string(argv[9]);
    }

    if (grpc_server_address.length() == 0) {
        // Start a gRPC server and wait for incoming connection before doing anything RaSTA
        RastaService svc(config,
                         rasta_channel1_address, rasta_channel1_port,
                         rasta_channel2_address, rasta_channel2_port,
                         rasta_local_id, rasta_target_id);

        grpc::EnableDefaultHealthCheckService(true);
        grpc::reflection::InitProtoReflectionServerBuilderPlugin();
        grpc::ServerBuilder builder;
        // Listen on the given address without any authentication mechanism.
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        // Register "service" as the instance through which we'll communicate with
        // clients. In this case it corresponds to an *synchronous* service.
        builder.RegisterService(&svc);
        // Finally assemble the server.
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        std::cout << "Server listening on " << server_address << std::endl;

        // Wait for the server to shutdown. Note that some other thread must be
        // responsible for shutting down the server for this call to ever return.
        server->Wait();
    } else {
        auto connectGrpc = [&]() {
            return std::thread([&]() {
                printf("Creating gRPC connection to %s...\n", grpc_server_address.c_str());
                auto channel = grpc::CreateChannel(grpc_server_address, grpc::InsecureChannelCredentials());
                auto stub = sci::Rasta::NewStub(channel);

                {
                    // Establish gRPC connection
                    std::lock_guard<std::mutex> guard(s_busy);
                    s_currentContext = std::make_unique<grpc::ClientContext>();
                    s_currentContext->AddMetadata("rasta-id", std::to_string(s_remote_id));
                    s_currentStream = stub->Stream(s_currentContext.get());
                }

                sci::SciPacket message;
                while (s_currentStream->Read(&message)) {
                    printf("Forwarding gRPC message...\n");
                    struct RastaByteArray *msg = reinterpret_cast<RastaByteArray *>(rmalloc(sizeof(struct RastaByteArray)));
                    allocateRastaByteArray(msg, message.message().size());
                    rmemcpy(msg->bytes, message.message().c_str(), message.message().size());

                    {
                        std::lock_guard<std::mutex> guard(s_fifo_mutex);
                        fifo_push(s_message_fifo, msg);
                    }

                    uint64_t notify_data = 1;
                    uint64_t ignore = write(s_data_fd, &notify_data, sizeof(uint64_t));
                    (void)ignore;
                }

                {
                    std::lock_guard<std::mutex> guard(s_busy);
                    s_currentStream = nullptr;
                    s_currentContext = nullptr;
                }

                uint64_t terminate = 1;
                uint64_t ignore = write(s_terminator_fd, &terminate, sizeof(uint64_t));
                (void)ignore;
            });
        };

        // Establish a RaSTA connection and connect to gRPC server afterwards
        processRasta(config,
                     rasta_channel1_address, rasta_channel1_port,
                     rasta_channel2_address, rasta_channel2_port,
                     rasta_local_id, rasta_target_id,
                     connectGrpc);
    }
    return 0;
}
