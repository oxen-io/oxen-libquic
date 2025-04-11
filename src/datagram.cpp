#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

#include <type_traits>

namespace oxen::quic
{

    DatagramIO::DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb) :
            IOChannel{c, e},
            dgram_data_cb{std::move(data_cb)},
            rbufsize{endpoint.datagram_bufsize()},
            recv_buffer{*this},
            _packet_splitting(_conn->packet_splitting_enabled())
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    std::shared_ptr<Stream> DatagramIO::get_stream()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return nullptr;
    }

    bool DatagramIO::is_closing_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return false;
    }
    bool DatagramIO::sent_fin() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return false;
    }
    void DatagramIO::set_fin(bool)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }
    size_t DatagramIO::unsent_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return _send_buffer.pending_bytes();
    }
    bool DatagramIO::has_unsent_impl() const
    {
        return not is_empty_impl();
    }
    void DatagramIO::wrote(size_t)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }
    std::vector<ngtcp2_vec> DatagramIO::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return {};
    }

    void DatagramIO::early_data_begin()
    {
        _send_buffer.early_data_begin();
    }
    void DatagramIO::early_data_retry()
    {
        _send_buffer.early_data_retry();
    }
    void DatagramIO::early_data_end(bool accepted)
    {
        _send_buffer.early_data_end(accepted);
    }

    void DatagramIO::set_split_datagram_lookahead(int n)
    {
        endpoint.call([this, val = n >= 0 ? static_cast<size_t>(n) : datagram_queue::DEFAULT_SPLIT_LOOKAHEAD] {
            log::debug(log_cat, "Changing split datagram lookahead from {} to {}", _send_buffer.split_lookahead, val);
            _send_buffer.split_lookahead = val;
        });
    }
    int DatagramIO::get_split_datagram_lookahead() const
    {
        return endpoint.call_get([this] { return static_cast<int>(_send_buffer.split_lookahead); });
    }

    dgram_interface::dgram_interface(Connection& c) : ci{c}, reference_id{ci.reference_id()} {}

    std::shared_ptr<connection_interface> dgram_interface::get_conn_interface()
    {
        return ci.shared_from_this();
    }

    void dgram_interface::reply(bspan data, std::shared_ptr<void> keep_alive)
    {
        ci.send_datagram(data, std::move(keep_alive));
    }

    void DatagramIO::send_impl(bspan data, std::shared_ptr<void> keep_alive)
    {
        endpoint.call([this, data, keep_alive = std::move(keep_alive)]() mutable {
            if (!_conn)
            {
                log::warning(log_cat, "Unable to send datagram: connection has gone away");
                return;
            }

            auto base_dgid = _next_dgram_counter++ << 2;
            _next_dgram_counter %= 1 << 14;

            log::trace(
                    log_cat,
                    "Connection ({}) queuing datagram with base dgid={:04x}: {}",
                    _conn->reference_id(),
                    base_dgid,
                    buffer_printer{data});

            _send_buffer.emplace(data, base_dgid, std::move(keep_alive));

            _conn->packet_io_ready();
        });
    }

    std::optional<prepared_datagram> DatagramIO::pending_datagram(bool prefer_small)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return _send_buffer.fetch(_conn->get_max_datagram_piece(), prefer_small);
    }

    void DatagramIO::confirm_datagram_sent()
    {
        _send_buffer.confirm_sent();
    }

    std::optional<std::vector<std::byte>> DatagramIO::to_buffer(bspan data, uint16_t dgid)
    {
        log::trace(log_cat, "DatagramIO handed datagram with endian swapped ID: {}", dgid);

        return recv_buffer.receive(data, dgid);
    }
}  // namespace oxen::quic
