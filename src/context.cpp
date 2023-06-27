#include "context.hpp"

#include "connection.hpp"

namespace oxen::quic
{
    void OutboundContext::handle_outbound_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Outboun context stored local address: {}", local);
    }

    void OutboundContext::handle_outbound_opt(opt::remote_addr addr)
    {
        remote = std::move(addr);
        log::trace(log_cat, "Outbound context stored remote address: {}", remote);
    }

    void OutboundContext::handle_outbound_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
        log::trace(log_cat, "Outbound context stored TLS credentials", remote);
    }

    void OutboundContext::handle_outbound_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void OutboundContext::handle_outbound_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Outbound context stored stream data callback");
        stream_data_cb = std::move(func);
    }

    void OutboundContext::handle_outbound_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Outbound context stored stream open callback");
        stream_open_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Inbound context stored bind address: {}", local);
    }

    void InboundContext::handle_inbound_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
        log::trace(log_cat, "Inbound context stored TLS credentials", remote);
    }

    void InboundContext::handle_inbound_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Inbound context stored stream data callback");
        stream_data_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Inbound context stored stream open callback");
        stream_open_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

}  // namespace oxen::quic
