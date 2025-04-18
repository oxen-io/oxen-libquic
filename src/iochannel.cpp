#include "iochannel.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

namespace oxen::quic
{

    IOChannel::IOChannel(Connection& c, Endpoint& e) :
            endpoint{e}, loop{endpoint.loop}, reference_id{c.reference_id()}, _conn{&c}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    std::shared_ptr<Connection> IOChannel::get_conn()
    {
        return loop.call_get([this] { return _conn ? _conn->shared_from_this() : nullptr; });
    }

    void IOChannel::send(std::string&& data)
    {
        auto keep_alive = std::make_shared<std::string>(std::move(data));
        std::string_view view{*keep_alive};
        send_impl(reinterpret_span<const std::byte>(view), std::move(keep_alive));
    }

    bool IOChannel::is_empty() const
    {
        return call_get_accessor(&IOChannel::is_empty_impl);
    }

    size_t IOChannel::unsent() const
    {
        return call_get_accessor(&IOChannel::unsent_impl);
    }

    bool IOChannel::has_unsent() const
    {
        return call_get_accessor(&IOChannel::has_unsent_impl);
    }

    bool IOChannel::is_closing() const
    {
        return call_get_accessor(&IOChannel::is_closing_impl);
    }

}  // namespace oxen::quic
