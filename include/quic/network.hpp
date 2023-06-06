#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <cstdint>
#include <memory>
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
        Network(std::shared_ptr<uvw::Loop> loop_ptr = nullptr);
        ~Network();

        std::shared_ptr<uvw::Loop> ev_loop;

        void run();

        // Main client endpoint creation function. If a local address is passed, then a dedicated
        // UDPHandle is bound to that address. If not, the universal UDPHandle is used for I/O. To
        // use this function four parameter structs can be passed:
        //
        //      local_addr                          OPTIONAL (if not, a random localhost:port
        //      {                                       will be assigned)
        //          std::string host,
        //          std::string port
        //      }
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
            // initialize client context and client tls context simultaneously
            std::shared_ptr<ClientContext> client_ctx =
                    std::make_shared<ClientContext>(quic_manager, std::forward<Opt>(opts)...);

            if (client_ctx->local)
            {
                client_ctx->udp_handle = handle_client_mapping(client_ctx->local);
            }
            else
            {
                client_ctx->udp_handle = quic_manager->universal_handle;
                client_ctx->local = quic_manager->default_local;
            }

            // ensure addresses stored correctly
            log::trace(log_cat, "Client local addr: {}:{}", client_ctx->local.ip.data(), client_ctx->local.port);
            log::trace(log_cat, "Client remote addr: {}:{}", client_ctx->remote.ip.data(), client_ctx->remote.port);

            // create client and then copy assign it to the client context so we can return
            // the shared ptr from this function
            auto client_ptr =
                    std::make_shared<Client>(quic_manager, client_ctx, (*client_ctx).conn_id, client_ctx->udp_handle);
            client_ctx->client = client_ptr;

            quic_manager->clients.emplace_back(std::move(client_ctx));
            log::trace(log_cat, "Client context emplaced");
            return client_ptr;
        };

        // Main server endpoint creation function. Binds a dedicated UDPHandle to the binding
        // address passed. To use this function, two parameter structs can be passed:
        //
        //      local_addr                              REQUIRED
        //      {
        //          std::string host,
        //          std::string port
        //      }
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
        //      server_data_callback_t server_data_cb   OPTIONAL (for test cases and error checking)
        //
        // If a client CA cert is passed, it will be used as the CA authority for the connections;
        // if a server callback is passed, then the user is expected to implement logic that will
        // handle certificate verification during GNUTLS' handshake; if nothing is passed, no client
        // verification will be implemented.
        //
        template <typename... Opt>
        std::shared_ptr<Server> server_listen(Opt&&... opts)
        {
            // initialize server context and server tls context simultaneously
            std::shared_ptr<ServerContext> server_ctx =
                    std::make_shared<ServerContext>(quic_manager, std::forward<Opt>(opts)...);

            // ensure address stored correctly
            log::trace(log_cat, "Server local addr: {}:{}", server_ctx->local.ip.data(), server_ctx->local.port);

            // UDP mapping
            auto udp_handle = handle_server_mapping(server_ctx->local);
            if (server_ctx->server_data_cb)
                udp_handle->once<uvw::UDPDataEvent>(server_ctx->server_data_cb);

            server_ctx->udp_handles[Address{server_ctx->local}] =
                    std::make_pair(udp_handle, std::move(server_ctx->temp_ctx));
            server_ctx->temp_ctx.reset();

            // make server
            server_ctx->server = std::make_shared<Server>(quic_manager, server_ctx);
            auto server_ptr = server_ctx->server;

            // emplace server context in handler set
            quic_manager->servers.emplace(server_ctx->local, server_ctx);
            // quic_manager->servers[server_ctx->local] = server_ctx;
            log::trace(log_cat, "Server context emplaced");
            return server_ptr;
        };

        void close();

      private:
        std::shared_ptr<Handler> quic_manager;
        std::unordered_map<Address, std::shared_ptr<uvw::UDPHandle>> mapped_client_addrs;
        std::unordered_map<Address, std::shared_ptr<uvw::UDPHandle>> mapped_server_addrs;

        std::shared_ptr<uvw::UDPHandle> handle_client_mapping(Address& local);

        std::shared_ptr<uvw::UDPHandle> handle_server_mapping(Address& local);

        void configure_client_handle(std::shared_ptr<uvw::UDPHandle> handle);

        void configure_server_handle(std::shared_ptr<uvw::UDPHandle> handle);

        void signal_config();
    };

}  // namespace oxen::quic
