#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"

#ifndef NDEBUG
// std::atomic<bool> oxen::quic::enable_datagram_drop_test;
// std::atomic<bool> oxen::quic::enable_datagram_flip_flop_test;
// std::atomic<int> oxen::quic::test_drop_counter;
// std::atomic<int> oxen::quic::test_flip_flop_counter;
#endif

namespace oxen::quic
{

    IOChannel::IOChannel(Connection& c, Endpoint& e) : conn{c}, endpoint{e}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    DatagramIO::DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb) :
            IOChannel{c, e},
            dgram_data_cb{std::move(data_cb)},
            recv_buffer{endpoint._rbufsize, *this},
            _packet_splitting(conn.packet_splitting_enabled())
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    void DatagramIO::send(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        // check this first and once; already considers policy when returning
        const auto max_size = conn.get_max_datagram_size();

        // we use >= instead of > for that just-in-case 1-byte cushion
        if (data.size() > max_size)
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
            bool oversize = (data.size() > half_size);  // if true, split this packet

            // incrementing the second half of a split datagram is done internally, so this should never be true
            assert(_last_dgram_id % 4 != 3);

            if (_packet_splitting && oversize)
            {
                // jump to the next size 4 block
                if (_last_dgram_id != 0)
                    _last_dgram_id += 4;

                // if the last dgram was unsplit, the previous increment needs an extra two
                if (_last_dgram_id % 4 == 0)
                    _last_dgram_id += 2;

                send_buffer.emplace(data, _last_dgram_id, std::move(keep_alive), dgram::OVERSIZED, max_size);
            }
            else
            {
                // if last dgram was split, increment by 2, else by 4
                _last_dgram_id += (_last_dgram_id % 4 == 2) ? 2 : 4;

                send_buffer.emplace(data, _last_dgram_id, std::move(keep_alive), dgram::STANDARD);
            }

            conn.packet_io_ready();
        });
    }

    prepared_datagram DatagramIO::pending_datagram(std::atomic<bool>& r)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        return send_buffer.prepare(r, _packet_splitting);
    }

    std::optional<bstring> DatagramIO::to_buffer(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "DatagramIO handed datagram with endian swapped ID: {}", dgid);

        // #ifndef NDEBUG
        //         if (conn.enable_datagram_flip_flop_test)
        //         {
        //             log::debug(log_cat, "enable_datagram_flip_flop_test is true, bypassing buffer");
        //             conn.test_flip_flop_counter += 1;
        //             log::debug(log_cat, "test counter: {}", conn.test_flip_flop_counter.load());
        //             return std::nullopt;
        //         }
        //         else
        //         {
        //             log::debug(log_cat, "enable_datagram_flip_flop_test is false, skipping optional logic");
        //         }

        // #endif

        return recv_buffer.receive(data, dgid);
    }
}  // namespace oxen::quic
