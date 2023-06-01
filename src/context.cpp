#include "context.hpp"

#include "client.hpp"
#include "connection.hpp"
#include "server.hpp"

namespace oxen::quic
{
    ClientContext::~ClientContext()
    {
        udp_handle->close();
        udp_handle->data(nullptr);
        udp_handle.reset();
    }

    std::shared_ptr<Endpoint> ClientContext::endpoint()
    {
        return client;
    }

    std::shared_ptr<Endpoint> ServerContext::endpoint()
    {
        return server;
    }

    void ClientContext::handle_clientctx_opt(opt::local_addr& addr)
    {
        local = addr;
        log::trace(log_cat, "Client stored local address: {}:{}", local.ip.data(), local.port);
    }

    void ClientContext::handle_clientctx_opt(opt::remote_addr& addr)
    {
        remote = addr;
        log::trace(log_cat, "Client stored remote address: {}:{}", remote.ip.data(), remote.port);
    }

    void ClientContext::handle_clientctx_opt(opt::client_tls& tls)
    {
        tls_ctx = std::move(tls).into_context();
    }

    void ClientContext::handle_clientctx_opt(client_tls_callback_t& func)
    {
        log::trace(log_cat, "Client given server certification callback");
        auto ctx = std::dynamic_pointer_cast<GNUTLSContext>(tls_ctx);
        if (func)
        {
            ctx->client_tls_cb = std::move(func);
            ctx->client_callback_init();
        }
    }

    void ServerContext::handle_serverctx_opt(opt::local_addr& addr)
    {
        local = addr;
        log::trace(log_cat, "Server stored bind address: {}:{}", local.ip.data(), local.port);
    }

    void ServerContext::handle_serverctx_opt(Address& addr)
    {
        local = addr;
        log::trace(log_cat, "Server stored bind address: {}:{}", local.ip.data(), local.port);
    }

    void ServerContext::handle_serverctx_opt(server_tls_callback_t& func)
    {
        log::trace(log_cat, "Server given client certification callback");
        auto ctx = std::dynamic_pointer_cast<GNUTLSContext>(temp_ctx);
        if (func)
        {
            ctx->server_tls_cb = std::move(func);
            ctx->server_callback_init();
        }
    }

    void ServerContext::handle_serverctx_opt(opt::server_tls& tls)
    {
        temp_ctx = std::move(tls).into_context();
    }

    void ServerContext::handle_serverctx_opt(server_data_callback_t& func)
    {
        log::trace(log_cat, "Server given data callback");
        server_data_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(stream_data_callback_t& func)
    {
        log::trace(log_cat, "Server given data callback");
        stream_data_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(stream_open_callback_t& func)
    {
        log::trace(log_cat, "Server given data callback");
        stream_open_cb = std::move(func);
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

}  // namespace oxen::quic
