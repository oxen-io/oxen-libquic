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
    /// Main library context 
    class Network
    {
        public:
            Network(std::shared_ptr<uvw::Loop> loop_ptr = nullptr);
            ~Network();

            std::shared_ptr<uvw::Loop> ev_loop;

            void
            init();

            int
            next_socket_id();

            Handler*
            get_quic();

            void
            listen(std::string host, uint16_t port);

            /****** NEW API ******/
            

            // Main client endpoint creation function. Binds a dedicated UDPHandle to the binding address passed.
            // To use this function, three parameters structs can be passed:
            //
            //      local_addr                      OPTIONAL (if not, a random localhost:port
            //      {                                   will be assigned)
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
            //          std::string client_cert             authentication by server)
            //
            //          std::string server_cert     (A) REQUIRED (pick ***one*** of options A/B/C)
            //          std::string server_CA       (B)
            //      }
            //      client_callback client_cb       (C)
            // 
            // TODO: ADD METHOD FOR SYSTEM CA VERIFICATION
            //  
            template <typename ... Opt>
            std::unique_ptr<Client>
            client_connect(Opt&&... opts)
            {
                // create UDP handle
                auto udp_handle = quic_manager->loop()->resource<uvw::UDPHandle>();
                auto conn_id = ConnectionID::random();

                // initialize client context and client tls context simultaneously
                std::shared_ptr<ClientContext> client_ctx = std::make_shared<ClientContext>(quic_manager, std::forward<Opt>(opts)...);
                
                // bind to local addr
                if (client_ctx->local)
                    udp_handle->bind(client_ctx->local);

                // connect to remote ep; will select random local if not passed
                udp_handle->connect(client_ctx->remote);

                // if no local addr is passed, populate with random local selected by UDPHandle
                if (!client_ctx->local)
                    client_ctx->local = Address{udp_handle->peer()};

                // make client
                client_ctx->client = std::make_shared<Client>(quic_manager, client_ctx, &conn_id);

                // fetch tls context stored in temp ptr in TLS creation
                auto temp_ctx = std::move(client_ctx->temp_ctx);

                // clear temp ptr
                client_ctx->temp_ctx.reset(nullptr);
                
                // emplace in client context
                auto pair = std::make_pair(udp_handle, std::move(temp_ctx));
                client_ctx->udp_handles.emplace(conn_id, std::move(pair));
            };


            // Main server endpoint creation function. Binds a dedicated UDPHandle to the binding address passed.
            // To use this function, two parameters structs can be passed:
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
            // TODO: ADD METHOD FOR SYSTEM CA CERTIFICATION
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

            // TODO: make this a client method s.t. clients can open multiple connections
            // as long as they already have one existing
            std::shared_ptr<Client>
            connect();

        private:
            void
            handle_client_opt(std::unique_ptr<ClientContext> client_ctx)
            {
                //
            };

            void
            handle_server_opt(std::unique_ptr<ServerContext> server_ctx)
            {
                //
            };

            /*********************/
        protected:
            std::shared_ptr<Handler> quic_manager;

            int 
            configure_tunnel(Handler* handler);

        public:
            /****** TEST FUNCTIONS ******/
            void
            shutdown_test();
            void
            listen_test(Address& local);
            void
            send_oneshot_test(Address& local, Address& remote, std::string msg="");
            // TOFIX: add cert verification to nullcert tests
            void
            listen_nullcert_test(Address& local, TLSCert cert);
            void
            send_oneshot_nullcert_test(Address& local, Address& remote, TLSCert cert, std::string msg="");
            /****************************/

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


    };

}   // namespace oxen::quic
