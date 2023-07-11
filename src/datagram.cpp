#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"

namespace oxen::quic
{
    IOChannel::IOChannel(Connection& c, Endpoint& e) : conn{c}, endpoint{e}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    DatagramIO::DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb) :
            IOChannel{c, e}, dgram_data_cb{std::move(data_cb)}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    void DatagramIO::send(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        const bool is_splitting = (conn.packet_splitting_policy() != Splitting::NONE);
        // check this first and once; already considers policy when returning
        const auto max_size = conn.get_max_datagram_size();

        // we use >= instead of > for that just-in-case 1-byte cushion
        if (data.size() >= max_size)
        {
            log::critical(
                    log_cat,
                    "Data of length {} cannot be sent with {} datagrams of max size {}",
                    data.size(),
                    is_splitting ? "unsplit" : "split",
                    max_size);
            throw std::invalid_argument{"Data too large to send as datagram with current policy"};
        }

        // if packet_splitting is lazy OR packet_splitting is off, send as "normal" datagram
        endpoint.call([this, data, keep_alive, is_splitting]() {
            log::trace(
                    log_cat,
                    "Connection (CID: {}) sending {} datagram: {}",
                    conn.scid(),
                    is_splitting ? "split" : "whole",
                    buffer_printer{data});
            append_buffer(data, keep_alive);
        });
    }

    void DatagramIO::append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        user_buffers.emplace_back(buffer, std::move(keep_alive));

        conn.packet_io_ready();
    }

    std::vector<ngtcp2_vec> DatagramIO::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::vector<ngtcp2_vec> bufs{};
        bufs.reserve(std::distance(user_buffers.begin(), user_buffers.end()));

        for (auto& b : user_buffers)
        {
            auto& temp = bufs.emplace_back();

            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(b.first.data()));
            temp.len = b.first.size();
        }

        return bufs;
    }

}  // namespace oxen::quic
