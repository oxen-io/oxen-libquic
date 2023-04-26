#pragma once

#include "context.hpp"
#include "handler.hpp"
#include "crypto.hpp"
#include "utils.hpp"

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

            // Creates and binds a dedicated UDPHandle to the bind_addr passed. This can be thought of as an undifferentiated 
            // endpoint until calls to Network::server or Network::client_connect are made. It can be used as such:
            // 
            //      auto ep = net.endpoint("127.0.0.1:1111", &tls_cert);
            //      auto server = net.server(ep, callbacks, ... )           // note, update signature here
            // 
            //      auto client1 = ep.client_connect
            // 
            // 
            // 
            std::unique_ptr<Endpoint>
            endpoint(Address& bind_addr, TLSCert& cert);

            // 
            std::unique_ptr<Server>
            server(std::unique_ptr<Endpoint>);

            // 
            std::unique_ptr<Client>
            client();

            // TODO: make this a client method s.t. clients can open multiple connections
            // as long as they already have one existing
            std::unique_ptr<Client>
            connect();

            template <typename ... Opt>
            std::unique_ptr<Client>
            client_connect(Opt&&... opts)
            {
                //
            };

            // Main server endpoint creation function. Binds a dedicated UDPHandle to the binding address passed.
            // To use this function, two parameters structs can be passed:
            //
            //      local_addr{std::string host, 
            //                 std::string port}
            //      server_tls{std::string server_key,          REQUIRED
            //                 std::string server_cert,         REQUIRED
            //                 std::string client_ca_cert,      OPTIONAL (do not pass both)
            //                 server_callback server_cb}       OPTIONAL (do not pass both)
            // 
            // If a client CA cert is passed, it will be used as the CA authority for the connections; if a server
            // callback is passed, then the user is expected to implement logic that will handle certificate verification
            // during GNUTLS' handshake; if nothing is passed, no client verification will be implemented.
            // 
            // TODO: ADD METHOD FOR SYSTEM CA CERTIFICATION
            // 
            template <typename ... Opt>
            std::unique_ptr<Server>
            server_listen(Opt&&... opts)
            {
                // initialize server context and server tls context simultaneously
                std::shared_ptr<ServerContext> server_ctx = std::make_shared<ServerContext>(quic_manager, std::forward<Opt>(opts)...);

                // make server
                server_ctx->server = std::make_unique<Server>(quic_manager, server_ctx);
                
                // emplace server context in handler set
                quic_manager->servers.emplace(Address{server_ctx->local}, server_ctx);
            };
            

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
