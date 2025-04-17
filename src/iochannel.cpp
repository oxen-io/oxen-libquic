#include "iochannel.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

namespace oxen::quic
{

    IOChannel::IOChannel(Connection& c, Endpoint& e) : endpoint{e}, reference_id{c.reference_id()}, _conn{&c}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
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

    Path IOChannel::path() const
    {
        return call_get_accessor(&Connection::path_impl);
    }

    Address IOChannel::local() const
    {
        return call_get_accessor(&Connection::local_impl);
    }

    Address IOChannel::remote() const
    {
        return call_get_accessor(&Connection::remote_impl);
    }

}  // namespace oxen::quic
