#include "context.hpp"
#include "client.hpp"
#include "server.hpp"


namespace oxen::quic
{
    ClientContext::~ClientContext()
    {
        udp_handle->close();
        udp_handle->data(nullptr);
        udp_handle.reset();
    }


    std::shared_ptr<Endpoint> 
    ClientContext::endpoint() 
    { 
        return client; 
    }


    std::shared_ptr<Endpoint> 
    ServerContext::endpoint()
    { 
        return server; 
    }


    void
    ClientContext::handle_clientctx_opt(opt::local_addr& addr)
    {
        fprintf(stderr, "Client passed local address: %s:%u\n", addr.ip.data(), addr.port);
        local = addr;
        fprintf(stderr, "Client stored local address: %s:%u\n", local.ip.data(), local.port);
    }


    void
    ClientContext::handle_clientctx_opt(opt::remote_addr& addr)
    {
        fprintf(stderr, "Client passed remote address: %s:%u\n", addr.ip.data(), addr.port);
        remote = addr;
        fprintf(stderr, "Client stored remote address: %s:%u\n", remote.ip.data(), remote.port);
    }


    void
    ClientContext::handle_clientctx_opt(opt::client_tls& tls)
    {
        tls_ctx = std::move(tls).into_context();
    }


    void
    ClientContext::handle_clientctx_opt(client_tls_callback_t func)
    {
        fprintf(stderr, "Client given server certification callback\n");
        client_cb = std::move(func);
    }

    void 
    ServerContext::handle_serverctx_opt(opt::local_addr& addr)
    {
        fprintf(stderr, "Server passed bind address: %s:%u\n", addr.ip.data(), addr.port);
        local = addr;
        fprintf(stderr, "Server stored bind address: %s:%u\n", local.ip.data(), local.port);
    }


    void 
    ServerContext::handle_serverctx_opt(Address& addr)
    {
        fprintf(stderr, "Server passed bind address: %s:%u\n", addr.ip.data(), addr.port);
        local = addr;
        fprintf(stderr, "Server stored bind address: %s:%u\n", local.ip.data(), local.port);
    }


    void
    ServerContext::handle_serverctx_opt(server_tls_callback_t& func)
    {
        fprintf(stderr, "Server given client certification callback\n");
        server_tls_cb = std::move(func);
    }


    void 
    ServerContext::handle_serverctx_opt(opt::server_tls& tls)
    {
        temp_ctx = std::move(tls).into_context();
    }


    void
    ServerContext::handle_serverctx_opt(server_data_callback_t& func)
    {
        fprintf(stderr, "Server given data callback\n");
        server_data_cb = std::move(func);
    }


    ServerContext::~ServerContext()
    {
        for (auto& h : udp_handles)
        {
            h.second.first->close();
            h.second.first->data(nullptr);
            h.second.first.reset();
            h.second.second.reset();
        }

        udp_handles.clear();
    }

    
}   // namespace oxen::quic
