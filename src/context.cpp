#include "context.hpp"

#include "connection.hpp"

namespace oxen::quic
{
    void IOContext::handle_ioctx_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
    }

    void IOContext::handle_ioctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void IOContext::handle_ioctx_opt(stream_close_callback func)
    {
        log::trace(log_cat, "Inbound context stored stream close callback");
        stream_close_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(stream_data_callback func)
    {
        log::trace(log_cat, "Outbound context stored stream data callback");
        stream_data_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(stream_open_callback func)
    {
        log::trace(log_cat, "Outbound context stored stream open callback");
        stream_open_cb = std::move(func);
    }
}  // namespace oxen::quic
