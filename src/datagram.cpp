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
            IOChannel{c, e}, dgram_data_cb{std::move(data_cb)}, _packet_splitting(conn.packet_splitting_enabled())
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    void DatagramIO::send(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        // check this first and once; already considers policy when returning
        const auto max_size = conn.get_max_datagram_size();

        // we use >= instead of > for that just-in-case 1-byte cushion
        if (data.size() >= max_size)
        {
            log::critical(
                    log_cat,
                    "Data of length {} cannot be sent with {} datagrams of max size {}",
                    data.size(),
                    _packet_splitting ? "unsplit" : "split",
                    max_size);
            throw std::invalid_argument{"Data too large to send as datagram with current policy"};
        }

        // if packet_splitting is lazy OR packet_splitting is off, send as "normal" datagram
        endpoint.call([this, data, keep_alive, max_size]() {
            log::trace(
                    log_cat,
                    "Connection (CID: {}) sending {} datagram: {}",
                    conn.scid(),
                    _packet_splitting ? "split" : "whole",
                    buffer_printer{data});

            auto half_size = max_size / 2;

            // only split if packet splitting and datagram needs to be split
            if (_packet_splitting && (data.size() > half_size))
            {
                assert(data.size() < max_size);
                // if _skip_next is true, then the last datagram sent was unsplit with an ID that is a
                // perfect multiple of 4. For the next split-datagram, we increment by 6 to get the id
                // for the first of the split-datagrams that satisfies (id % 4) == 2
                //
                // if _skip_next is false, then the last datagram sent was unsplit with an ID that
                // satisfies (id % 4) == 3. For the next split-datagram, we increment by 3 to ge the id
                // for the first of the split-datagrams that satisfies (id % 4) == 2
                _last_dgram_id += (_skip_next) ? 6 : 3;

                auto first_half = data.substr(0, half_size), second_half = data.substr(half_size);

                std::shared_ptr<void> keep_copy(keep_alive);
                send_buffer.emplace_back(_last_dgram_id, std::make_pair(first_half, std::move(keep_copy)));

                _last_dgram_id += 1;
                send_buffer.emplace_back(_last_dgram_id, std::make_pair(second_half, std::move(keep_alive)));

                _skip_next = false;
            }
            else
            {
                _last_dgram_id += 4;
                send_buffer.emplace_back(_last_dgram_id, std::make_pair(data, std::move(keep_alive)));
                _skip_next = true;
            }

            conn.packet_io_ready();
        });
    }

    std::vector<ngtcp2_vec> DatagramIO::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::vector<ngtcp2_vec> bufs{};
        bufs.reserve(2);

        auto& b = send_buffer.front();

        auto& did = bufs.emplace_back();
        did.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&b));
        did.len = 2;

        auto& dat = bufs.emplace_back();
        dat.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(b.second.first.data()));
        dat.len = b.second.first.size();

        return bufs;
    }

    prepared_datagram DatagramIO::pending_datagram()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::pair<uint64_t, std::vector<ngtcp2_vec>> bufs;
        bufs.second.reserve(2);

        auto& b = send_buffer.front();

        prepared_datagram d{};
        d.id = b.first;
        d.bufs_len = 1;

        oxenc::write_host_as_big(static_cast<uint16_t>(b.first), d.dgid.data());

        if (_packet_splitting)
        {
            log::trace(log_cat, "We are inside packet splitting");
            d.bufs[0].base = d.dgid.data();
            d.bufs[0].len = 2;
            d.bufs_len++;
        }

        d.bufs[d.bufs_len - 1].base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(b.second.first.data()));
        d.bufs[d.bufs_len - 1].len = b.second.first.size();

        return d;

        // bufs.first = b.first;

        // auto& did = bufs.second.emplace_back();
        // did.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&b.first));
        // did.len = 2;

        // auto& dat = bufs.second.emplace_back();
        // dat.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(b.second.first.data()));
        // dat.len = b.second.first.size();

        // return bufs;
    }
}  // namespace oxen::quic

/*
outbound:
    uint16_t dgid = 123; // calculated however. Can be a type longer than uint16_t if 16 bits isn't enough.
    std::array<uint8_t, 2> dgid_bytes;
    oxenc::write_host_as_big(dgid, dgid_bytes.data());

inbound:
    uint16_t dgid = oxenc::load_big_to_host<uint16_t>(bytes.data());

*/
