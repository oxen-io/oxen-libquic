#pragma once

#include "client.hpp"
#include "context.hpp"
#include "handler.hpp"
#include "crypto.hpp"
#include "utils.hpp"
#include "uvw/udp.h"

#include <gnutls/gnutls.h>
#include <uvw.hpp>

#include <cstdint>

#include <memory>


namespace oxen::quic
{
    /*
        TODO:
            - add methods for system CA verification to client_connect and server_listen pathways
            - make Network::connect(...) a client method s.t. multiple connections can be opened
              given that one already exists
    
    */

    /// Main library context 
    class Network
    {
        public:
            Network(std::shared_ptr<uvw::Loop> loop_ptr = nullptr);
            ~Network();

            std::shared_ptr<uvw::Loop> ev_loop;

            Handler*
            get_quic();

            /****** NEW API ******/

            // Main client endpoint creation function. If a local address is passed, then a dedicated UDPHandle
            // is bound to that address. If not, UVW will pick a random local port and bind to it. To use this
            // function, four parameter structs can be passed:
            //
            //      local_addr                      OPTIONAL (if not, a random localhost:port
            //      {                               will be assigned)
            //          std::string host,
            //          std::string port
            //      }
            //      remote_addr                     REQUIRED
            //      {
            //          std::string host,
            //          std::string port
            //      }
            //      client_tls                      REQUIRED
            //      {                                  
            //          std::string client_key,     OPTIONAL (required if using client certificate 
            //          std::string client_cert     authentication by server)
            //
            //          std::string server_cert     (A) REQUIRED (pick ***one*** of options A/B/C)
            //          std::string server_CA       (B)
            //      }
            //      client_callback client_cb       (C)
            //  
            template <typename ... Opt>
            std::shared_ptr<Client>
            client_connect(Opt&&... opts)
            {
                // create UDP handle/conn_id's to use later for emplacing into maps
                auto udp_handle = quic_manager->loop()->resource<uvw::UDPHandle>();
                auto conn_id = ConnectionID::random();

                // initialize client context and client tls context simultaneously
                std::shared_ptr<ClientContext> client_ctx = std::make_shared<ClientContext>(quic_manager, std::forward<Opt>(opts)...);
                
                // bind to local addr (if passed)
                if (client_ctx->local)
                    udp_handle->bind(client_ctx->local);

                // connect to remote ep; will select random local if not specified to client_connect
                udp_handle->connect(client_ctx->remote);

                // if no local addr is passed, populate with random local selected by UDPHandle
                if (!client_ctx->local)
                    client_ctx->local = Address{udp_handle->peer()};

                // create client and then copy assign it to the client context so we can return
                // the shared ptr from this function
                client_ctx->client = std::make_shared<Client>(quic_manager, client_ctx, &conn_id);

                // fetch tls context stored in temp ptr in TLS creation; clear temp ptr
                auto temp_ctx = std::move(client_ctx->temp_ctx);
                client_ctx->temp_ctx.reset(nullptr);
                
                // emplace in client context
                client_ctx->udp_handles.emplace(conn_id, std::make_pair(udp_handle, std::move(temp_ctx)));

                // clear local and remote address members

                return client_ctx->client;
            };


            // Main server endpoint creation function. Binds a dedicated UDPHandle to the binding address passed.
            // To use this function, two parameter structs can be passed:
            //
            //      local_addr                          REQUIRED
            //      {
            //          std::string host, 
            //          std::string port
            //      }
            //      server_tls                          REQUIRED
            //      {
            //          std::string server_key,         REQUIRED
            //          std::string server_cert,        REQUIRED
            //          std::string client_ca_cert,     OPTIONAL (do not pass this and server_cb)
            //      }
            //      server_callback server_cb           OPTIONAL (do not pass this and client_ca_cert)
            //
            // If a client CA cert is passed, it will be used as the CA authority for the connections; if a server
            // callback is passed, then the user is expected to implement logic that will handle certificate verification
            // during GNUTLS' handshake; if nothing is passed, no client verification will be implemented.
            // 
            template <typename ... Opt>
            std::shared_ptr<Server>
            server_listen(Opt&&... opts)
            {
                // initialize server context and server tls context simultaneously
                std::shared_ptr<ServerContext> server_ctx = std::make_shared<ServerContext>(quic_manager, std::forward<Opt>(opts)...);

                // make server
                server_ctx->server = std::make_shared<Server>(quic_manager, server_ctx);
                
                // emplace server context in handler set
                quic_manager->servers.emplace(Address{server_ctx->local}, server_ctx);

                return server_ctx->server;
            };

            
            std::shared_ptr<Client>
            client(Address& bind_addr, TLSCert& cert);
            std::shared_ptr<Server>
            server(std::unique_ptr<Endpoint>);

            std::shared_ptr<Client>
            connect();

            /*********************/

        protected:
            std::shared_ptr<Handler> quic_manager;

        public:
            /*
            template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
            void
            udp_connect(
                Address& local, Address& remote, T cert, open_callback open_cb = NULL, close_callback close_cb = NULL)
            {
                auto ep = get_quic();
                if (ep == nullptr)
                {
                    fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
                    return;
                }

                open_callback on_open = [open = std::move(open_cb)](bool success, void* user_data) 
                {
                    fprintf(stderr, "QUIC tunnel opened %s\n", (success) ? "successfully" : "unsuccessfully");

                    if (open)
                        open(success, user_data);
                };

                close_callback on_close = [&remote, close = std::move(close_cb)](int rv, void* user_data)
                {
                    fprintf(stderr, "QUIC tunnel closed to %s:%d\n", remote.ip.c_str(), remote.port);

                    if (close)
                        close(rv, user_data);
                };

                try 
                {
                    auto rv = ep->udp_connect(local, remote, std::move(cert), std::move(on_open), std::move(on_close));
                }
                catch (std::exception& e)
                {
                    fprintf(stderr, "Exception:%s\n", e.what());
                }
                catch (int err)
                {
                    fprintf(stderr, "Error: opening QUIC tunnel [code: %d]", err);
                }
            }
            */

    };

}   // namespace oxen::quic
