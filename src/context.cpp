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

    void ClientContext::handle_clientctx_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
    }

    void ClientContext::handle_clientctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void ClientContext::handle_clientctx_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Client given stream data callback");
        stream_data_cb = std::move(func);
    }

    void ClientContext::handle_clientctx_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Client given stream open callback");
        stream_open_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Server stored bind address: {}", local);
    }

    void ServerContext::handle_serverctx_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
    }

    void ServerContext::handle_serverctx_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Server given stream data callback");
        stream_data_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Server given stream open callback");
        stream_open_cb = std::move(func);
    }

    void ServerContext::handle_serverctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

}  // namespace oxen::quic
