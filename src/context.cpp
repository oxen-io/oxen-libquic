#include "context.hpp"

#include "connection.hpp"
#include "internal.hpp"

namespace oxen::quic
{
    void IOContext::_init()
    {
        if (tls_creds == nullptr)
            throw std::runtime_error{"Session IOContext requires some form of TLS credentials to operate"};

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

    void IOContext::handle_ioctx_opt(opt::disable_key_verification)
    {
        log::info(
                log_cat,
                "IOContext disabling key verification for {}bound connections!",
                dir == Direction::INBOUND ? "in" : "out");
        disable_key_verification = true;
    }
}  // namespace oxen::quic
