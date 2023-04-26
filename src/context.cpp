#include "utils.hpp"
#include "context.hpp"
#include "client.hpp"


namespace oxen::quic
{
    ClientContext::~ClientContext()
    {
        if (udp_handle)
        {
            udp_handle->close();
            udp_handle->data(nullptr);
            udp_handle.reset();
        }

        for (auto h : udp_handles)
        {
            h->close();
            h->data(nullptr);
            h.reset();
        }
    }


    void
    ClientContext::set_addrs(uvw::Addr &local_addr, uvw::Addr &remote_addr)
    {
        set_local(local_addr);
        set_remote(remote_addr);
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
