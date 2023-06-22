#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <uvw.hpp>

#include "client.hpp"
#include "context.hpp"
#include "crypto.hpp"
#include "handler.hpp"
#include "server.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Network
    {
        friend class Handler;

      public:
        Network(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id loop_thread_id);
        Network();
        ~Network();

        std::shared_ptr<uvw::loop> ev_loop;
        std::unique_ptr<std::thread> loop_thread;

        // Main client endpoint creation function. If a local address is passed, then a dedicated
        // uv_udt_t is bound to that address. To use this function four parameter structs can be
        // passed:
        //
        //      local_addr                          OPTIONAL (if not, the "any" address will be used)
        //      {
        //          std::string host,
        //          uint16_t port
        //      }
        //      or local_addr{uint16_t port} for any address with the given port.
        //
        //      remote_addr                         REQUIRED
        //      {
        //          std::string host,
        //          std::string port
        //      }
        //      client_tls                          REQUIRED
        //      {
        //          std::string client_key,         OPTIONAL (required if using client certificate
        //          std::string client_cert             authentication by server)
        //
        //          std::string server_cert         (A) REQUIRED (pick ***one*** of options A/B/C)
        //          std::string server_CA           (B)
        //      }
        //      client_tls_callback_t client_tls_cb (C)
        //
        template <typename... Opt>
        std::shared_ptr<Client> client_connect(Opt&&... opts)
        {
            std::promise<std::shared_ptr<Client>> p;
            auto f = p.get_future();
            quic_manager->call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    std::shared_ptr<ClientContext> client_ctx =
                            std::make_shared<ClientContext>(quic_manager, std::forward<Opt>(opts)...);

                    client_ctx->udp_handle = handle_mapping(false, client_ctx->local);

                    // ensure addresses stored correctly
                    log::trace(log_cat, "Client local addr: {}", client_ctx->local);
                    log::trace(log_cat, "Client remote addr: {}", client_ctx->remote);

                    // create client and then copy assign it to the client context so we can return
                    // the shared ptr from this function
                    auto client_ptr = std::make_shared<Client>(
                            quic_manager, client_ctx, (*client_ctx).conn_id, client_ctx->udp_handle);
                    client_ctx->client = client_ptr;

                    quic_manager->clients.emplace_back(std::move(client_ctx));
                    log::trace(log_cat, "Client context emplaced");

                    p.set_value(client_ptr);
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

        // Main server endpoint creation function. Binds a dedicated uv_udt_t to the binding
        // address passed. To use this function, two parameter structs can be passed:
        //
        //      local_addr                              REQUIRED
        //      {
        //          std::string host,
        //          uint16_t port
        //      } or local_addr{uint16_t port} for all addresses with a given port.
        //
        //      server_tls                              REQUIRED
        //      {
        //          std::string server_key,             REQUIRED
        //          std::string server_cert,            REQUIRED
        //          std::string client_ca_cert,         OPTIONAL (do not pass this and
        //          server_tls_cb)
        //      }
        //      server_tls_callback_t server_tls_cb     OPTIONAL (do not pass this and
        //      client_ca_cert)
        //
        // If a client CA cert is passed, it will be used as the CA authority for the connections;
        // if a server callback is passed, then the user is expected to implement logic that will
        // handle certificate verification during GNUTLS' handshake; if nothing is passed, no client
        // verification will be implemented.
        //
        template <typename... Opt>
        std::shared_ptr<Server> server_listen(Opt&&... opts)
        {
            std::promise<std::shared_ptr<Server>> p;
            auto f = p.get_future();
            quic_manager->call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize server context and server tls context simultaneously
                    std::shared_ptr<ServerContext> server_ctx =
                            std::make_shared<ServerContext>(quic_manager, std::forward<Opt>(opts)...);

                    // ensure address stored correctly
                    log::trace(log_cat, "Server local addr: {}", server_ctx->local);

                    auto& [udp, tls] = server_ctx->udp_handles[server_ctx->local];
                    if (udp)
                        throw std::runtime_error{
                                "Unable to start server: we already have a server listening on that address"};

                    // UDP mapping
                    udp = handle_mapping(true, server_ctx->local);
                    tls = server_ctx->tls_creds;

                    // make server
                    server_ctx->server = std::make_shared<Server>(quic_manager, server_ctx);
                    auto server_ptr = server_ctx->server;

                    // emplace server context in handler set
                    quic_manager->servers.emplace(server_ctx->local, server_ctx);
                    // quic_manager->servers[server_ctx->local] = server_ctx;
                    log::trace(log_cat, "Server context emplaced");
                    p.set_value(server_ptr);
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

        void close();

      private:
        std::atomic<bool> running{false};

        std::shared_ptr<Handler> quic_manager;
        std::unordered_map<Address, std::shared_ptr<uv_udp_t>> mapped_client_addrs;
        std::unordered_map<Address, std::shared_ptr<uv_udp_t>> mapped_server_addrs;

        std::shared_ptr<uv_udp_t> handle_mapping(bool server, const Address& local);

        std::shared_ptr<uv_udp_t> start_udp_handle(uv_loop_t* loop, bool server, const Address& bind);

        void signal_config();
    };

}  // namespace oxen::quic
