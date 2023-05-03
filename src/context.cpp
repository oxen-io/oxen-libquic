#include "context.hpp"
#include "client.hpp"


namespace oxen::quic
{
    ClientContext::~ClientContext()
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


    void
    ClientContext::handle_clientctx_opt(opt::local_addr& addr)
    {
        fprintf(stderr, "Client passed local address: %s\n", addr.string_addr.data());
        set_local(addr);
    }


    void
    ClientContext::handle_clientctx_opt(opt::remote_addr& addr)
    {
        fprintf(stderr, "Client passed remote address: %s\n", addr.string_addr.data());
        set_remote(addr);
    }


    void
    ClientContext::handle_clientctx_opt(opt::client_tls& tls)
    {
        temp_ctx = std::move(tls).into_context();
    }


    void
    ClientContext::handle_clientctx_opt(client_callback& func)
    {
        fprintf(stderr, "Client given server certification callback\n");
        client_cb = std::move(func);
    }

    void 
    ServerContext::handle_serverctx_opt(opt::local_addr& addr)
    {
        fprintf(stderr, "Server passed bind address: %s\n", addr.string_addr.data());
        set_addr(addr);
    }


    void
    ServerContext::handle_serverctx_opt(server_callback& func)
    {
        fprintf(stderr, "Server given client certification callback\n");
        server_cb = std::move(func);
    }


    void 
    ServerContext::handle_serverctx_opt(opt::server_tls& tls)
    {
        tls_ctx = std::move(tls).into_context();
    }


    ServerContext::~ServerContext()
    {
        if (udp_handle)
        {
            udp_handle->close();
            udp_handle->data(nullptr);
            udp_handle.reset();
        }
    }

    
}   // namespace oxen::quic
