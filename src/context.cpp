#include "context.hpp"

#include "internal.hpp"
#include "stream.hpp"

#include <fmt/ranges.h>

#include <stdexcept>

namespace oxen::quic
{
    void IOContext::_init()
    {
        if (dir == Direction::INBOUND && (!tls_creds || !tls_creds->has_credentials()))
            throw std::logic_error{"listen() requires full TLS credentials"};
        // For outbound we allow no creds; connect will create a default, non-credential object if
        // we give it a outbound null creds.

        log::debug(log_cat, "{} IO context created successfully", (dir == Direction::OUTBOUND) ? "Outbound"s : "Inbound"s);
    }

    void IOContext::handle_ioctx_opt(std::shared_ptr<TLSCreds> tls)
    {
        tls_creds = std::move(tls);
    }

    void IOContext::handle_ioctx_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void IOContext::handle_ioctx_opt(opt::keep_alive ka)
    {
        config.keep_alive = ka.time;
        log::trace(log_cat, "User passed connection keep_alive config value: {}", config.keep_alive.count());
    }

    void IOContext::handle_ioctx_opt(opt::idle_timeout ito)
    {
        config.idle_timeout = ito.timeout;
        log::trace(log_cat, "User passed connection idle_timeout config value: {}", config.idle_timeout.count());
    }

    void IOContext::handle_ioctx_opt(opt::handshake_timeout hto)
    {
        config.handshake_timeout = hto.timeout;
        log::trace(log_cat, "User passed connection handshake_timeout config value: {}", config.handshake_timeout->count());
    }

    void IOContext::handle_ioctx_opt(opt::outbound_alpns alpns)
    {
        config.out_alpns.emplace(std::move(alpns));
        log::trace(log_cat, "User passed connection outbound ALPN override: {}", fmt::join(config.out_alpns->alpns, ","));
    }

    void IOContext::handle_ioctx_opt(stream_data_callback func)
    {
        log::trace(log_cat, "IO context stored stream close callback");
        stream_data_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(stream_open_callback func)
    {
        log::trace(log_cat, "IO context stored stream open callback");
        stream_open_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(stream_close_callback func)
    {
        log::trace(log_cat, "IO context stored stream open callback");
        stream_close_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(opt::stream_fin_callback cb)
    {
        log::trace(log_cat, "IO context stored stream fin callback, {}", !!cb.cb);
        stream_fin_cb = std::move(cb);
    }

    void IOContext::handle_ioctx_opt(stream_constructor_callback func)
    {
        log::trace(log_cat, "IO context stored stream constructor callback");
        stream_construct_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(dgram_data_callback func)
    {
        log::trace(log_cat, "IO context stored datagram data callback");
        dgram_data_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(connection_established_callback func)
    {
        log::trace(log_cat, "IO context stored connection established callback");
        conn_established_cb = std::move(func);
    }

    void IOContext::handle_ioctx_opt(connection_closed_callback func)
    {
        log::trace(log_cat, "IO context stored connection closed callback");
        conn_closed_cb = std::move(func);
    }

}  // namespace oxen::quic
