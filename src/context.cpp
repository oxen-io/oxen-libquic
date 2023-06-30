#include "context.hpp"

#include "connection.hpp"

namespace oxen::quic
{
    void OutboundContext::handle_outbound_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
    }

    void OutboundContext::handle_outbound_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void OutboundContext::handle_outbound_opt(stream_close_callback func)
    {
        log::trace(log_cat, "Inbound context stored stream close callback");
        stream_close_cb = std::move(func);
    }

    void OutboundContext::handle_outbound_opt(stream_data_callback func)
    {
        log::trace(log_cat, "Outbound context stored stream data callback");
        stream_data_cb = std::move(func);
    }

    void OutboundContext::handle_outbound_opt(stream_open_callback func)
    {
        log::trace(log_cat, "Outbound context stored stream open callback");
        stream_open_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
        log::trace(log_cat, "Inbound context stored TLS credentials");
    }

    void InboundContext::handle_inbound_opt(stream_data_callback func)
    {
        log::trace(log_cat, "Inbound context stored stream data callback");
        stream_data_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(stream_open_callback func)
    {
        log::trace(log_cat, "Inbound context stored stream open callback");
        stream_open_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(stream_close_callback func)
    {
        log::trace(log_cat, "Inbound context stored stream close callback");
        stream_close_cb = std::move(func);
    }

    void InboundContext::handle_inbound_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

}  // namespace oxen::quic
