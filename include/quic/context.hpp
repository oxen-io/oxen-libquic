#pragma once

#include "utils.hpp"
#include "crypto.hpp"
#include "handler.hpp"
#include "uvw/udp.h"

#include <memory>
#include <uvw.hpp>

#include <unordered_set>


namespace oxen::quic
{
    class Server;
    class Client;

    struct ClientContext
	{
		// Client endpoint linked to this instance
		std::shared_ptr<Client> client;
		Address local, remote;
        client_callback client_cb;
        std::shared_ptr<Handler> quic_manager;
        std::unique_ptr<TLSContext> temp_ctx;   // used for creating clientcontext, cleared immediately

        // Cert information for each connection is stored in a map indexed by ConnectionID.
        // As a result, each connection (also mapped in client->conns) can have its own
        // TLS cert info. Each connection also stores within it the gnutls_session_t and
        // gnutls_certificate_credentials_t objects used to initialize its ngtcp2 things
        std::unordered_map<
            ConnectionID, 
            std::pair<std::shared_ptr<uvw::UDPHandle>, std::unique_ptr<TLSContext>>> udp_handles;

        inline void
        set_addrs(uvw::Addr& local_addr, uvw::Addr& remote_addr)
        {
            set_local(local_addr);
            set_remote(remote_addr);
        };
        inline void
        set_local(uvw::Addr& addr) { local = Address{addr}; };
        inline void
        set_remote(uvw::Addr& addr) { remote = Address{addr}; };

        void
        handle_clientctx_opt(opt::local_addr& addr);
        void
        handle_clientctx_opt(opt::remote_addr& addr);
        void
        handle_clientctx_opt(opt::client_tls& tls);
        void
        handle_clientctx_opt(client_callback& func);

        template <typename ... Opt>
        ClientContext(std::shared_ptr<Handler> quic_ep, Opt&&... opts)
        {
            fprintf(stderr, "Making client context...\n");

            // copy assign handler shared_ptr
            quic_manager = quic_ep;
            // parse all options
            handle_clientctx_opt(std::forward<Opt>(opts)...);
            // ensure remote_addr was passed
            assert(remote);

            fprintf(stderr, "Client context successfully created\n");
        }

		~ClientContext();
	};


    struct ServerContext
    {
        // Server endpoint linked to this instance
        std::shared_ptr<Server> server;
        Address local;
        server_callback server_cb;
        std::shared_ptr<uvw::UDPHandle> udp_handle;
        std::unique_ptr<TLSContext> tls_ctx;
        std::shared_ptr<Handler> quic_manager;

        inline void
        set_addr(uvw::Addr& addr) { local = Address{addr}; };

        void 
        handle_serverctx_opt(opt::local_addr& addr);
        void 
        handle_serverctx_opt(opt::server_tls& tls);
        void
        handle_serverctx_opt(server_callback& func);

        template <typename ... Opt>
        ServerContext(std::shared_ptr<Handler> quic_ep, Opt&&... opts)
        {
            fprintf(stderr, "Making server context...\n");

            // copy assign handler shared_ptr
            quic_manager = quic_ep;
            // parse all options
            handle_serverctx_opt(std::forward<Opt>(opts)...);
            // make UDP handle
            udp_handle = quic_manager->ev_loop->resource<uvw::UDPHandle>();
            udp_handle->bind(local);
            udp_handle->recv();

            fprintf(stderr, "Server context successfully created\n");
        }

        ~ServerContext();
    };


}   // namespac oxen::quic
