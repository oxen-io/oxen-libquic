#pragma once

#include "utils.hpp"
#include "crypto.hpp"
#include "handler.hpp"

#include <uvw.hpp>

#include <unordered_set>


namespace oxen::quic
{
    class Server;
    class Client;

    struct ClientContext
	{
		// Client endpoint linked to this instance
		std::unique_ptr<Client> client;
		Address local, remote;

		open_callback open_cb;
		close_callback close_cb;

		// UDP handles
        std::unordered_set<std::shared_ptr<uvw::UDPHandle>> udp_handles;
		std::shared_ptr<uvw::UDPHandle> udp_handle;

        // Cert information for each connection is stored in a map indexed by ConnectionID.
        // As a result, each connection (also mapped in client->conns) can have its own
        // TLS cert info. Each connection also stores within it the gnutls_session_t and
        // gnutls_certificate_credentials_t objects used to initialize its ngtcp2 things
        std::unordered_map<ConnectionID, std::unique_ptr<TLSContext>> cert_managers;

        void
        set_addrs(uvw::Addr& local_addr, uvw::Addr& remote_addr);

        inline void
        set_local(uvw::Addr& addr) { local = Address{addr}; };

        inline void
        set_remote(uvw::Addr& addr) { remote = Address{addr}; };

		~ClientContext();
	};


    struct ServerContext
    {
        // Server endpoint linked to this instance
        std::unique_ptr<Server> server;
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
            
            // parse all options
            handle_serverctx_opt(std::forward<Opt>(opts)...);
            // copy assign handler shared_ptr
            quic_manager = quic_ep;
            // make UDP handle
            udp_handle = quic_manager->ev_loop->resource<uvw::UDPHandle>();
            udp_handle->bind(local);
            udp_handle->recv();

            fprintf(stderr, "Server context successfully created\n");
        }

        ~ServerContext();
    };


}   // namespac oxen::quic
