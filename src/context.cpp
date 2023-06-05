#include "context.hpp"

#include "client.hpp"
#include "connection.hpp"
#include "server.hpp"

namespace oxen::quic
{
    std::shared_ptr<Endpoint> ClientContext::endpoint()
    {
        return client;
    }

    std::shared_ptr<Endpoint> ServerContext::endpoint()
    {
        return server;
    }

    void ClientContext::handle_clientctx_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Client stored local address: {}", local);
    }

    void ClientContext::handle_clientctx_opt(opt::remote_addr addr)
    {
        remote = std::move(addr);
        log::trace(log_cat, "Client stored remote address: {}", remote);
    }

    void ClientContext::handle_clientctx_opt(opt::client_tls tls)
    {
        tls_ctx = std::move(tls).into_context();
    }

    void ClientContext::handle_clientctx_opt(client_tls_callback_t func)
    {
        log::trace(log_cat, "Client given server certification callback");
        auto ctx = std::dynamic_pointer_cast<GNUTLSContext>(tls_ctx);
        if (func)
        {
            ctx->client_tls_cb = std::move(func);
            ctx->client_callback_init();
        }
    }

    void ClientContext::handle_clientctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void ServerContext::handle_serverctx_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Server stored bind address: {}", local);
    }

    void ServerContext::handle_serverctx_opt(Address addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Server stored bind address: {}", local);
    }

    void ServerContext::handle_serverctx_opt(server_tls_callback_t func)
    {
        log::trace(log_cat, "Server given client certification callback");
        auto ctx = std::dynamic_pointer_cast<GNUTLSContext>(temp_ctx);
        if (func)
        {
            ctx->server_tls_cb = std::move(func);
            ctx->server_callback_init();
        }
    }

    void ServerContext::handle_serverctx_opt(opt::server_tls tls)
    {
        temp_ctx = std::move(tls).into_context();
    }

    void ServerContext::handle_serverctx_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Server given data callback");
        stream_data_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Server given data callback");
        stream_open_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

}  // namespace oxen::quic
