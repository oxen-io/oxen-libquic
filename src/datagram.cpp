#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

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

    int64_t DatagramIO::stream_id() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return std::numeric_limits<int64_t>::min();
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
    };
    size_t DatagramIO::unsent_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        size_t sum{0};
        if (send_buffer.empty())
            return sum;
        for (const auto& entry : send_buffer.buf)
            sum += entry.size();
        return sum;
    }
    bool DatagramIO::has_unsent_impl() const
    {
        return not is_empty_impl();
    }
    void DatagramIO::wrote(size_t)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    };
    std::vector<ngtcp2_vec> DatagramIO::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return {};
    }

    dgram_interface::dgram_interface(Connection& c) : ci{c}, reference_id{ci.reference_id()} {}

    std::shared_ptr<connection_interface> dgram_interface::get_conn_interface()
    {
        return ci.shared_from_this();
    }

    void dgram_interface::reply(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        ci.send_datagram(data, std::move(keep_alive));
    }

    void DatagramIO::send_impl(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        // if packet_splitting is lazy OR packet_splitting is off, send as "normal" datagram
        endpoint.call([this, data, keep_alive = std::move(keep_alive)]() {
            if (!_conn)
            {
                log::warning(log_cat, "Unable to send datagram: connection has gone away");
                return;
            }

            // check this first and once; already considers policy when returning
            const auto max_size = _conn->get_max_datagram_size_impl();

            // we use >= instead of > for that just-in-case 1-byte cushion
            if (data.size() > max_size)
            {
                log::warning(
                        log_cat,
                        "Data of length {} cannot be sent with {} datagrams of max size {}",
                        data.size(),
                        _packet_splitting ? "unsplit" : "split",
                        max_size);
                // Ideally we would throw, but because we're inside a `call` and are probably
                // running after the `send_impl` call returned, all we can really do is warn and
                // drop.
                return;
            }

            log::trace(
                    log_cat,
                    "Connection ({}) sending {} datagram: {}",
                    _conn->reference_id(),
                    _packet_splitting ? "split" : "whole",
                    buffer_printer{data});

            bool split = _packet_splitting && data.size() > max_size / 2;

            auto dgram_id = _next_dgram_counter << 2;
            if (split)
                dgram_id |= 0b10;
            (++_next_dgram_counter) %= 1 << 14;

            send_buffer.emplace(data, dgram_id, std::move(keep_alive), split ? dgram::OVERSIZED : dgram::STANDARD, max_size);

            _conn->packet_io_ready();
        });
    }

    prepared_datagram DatagramIO::pending_datagram(bool r)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        return send_buffer.prepare(r, _packet_splitting);
    }

    std::optional<bstring> DatagramIO::to_buffer(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "DatagramIO handed datagram with endian swapped ID: {}", dgid);

        return recv_buffer.receive(data, dgid);
    }
}  // namespace oxen::quic
