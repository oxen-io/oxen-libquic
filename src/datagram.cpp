#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"

std::atomic<bool> oxen::quic::enable_test_features;
std::atomic<int> oxen::quic::test_counter;

namespace oxen::quic
{

    IOChannel::IOChannel(Connection& c, Endpoint& e) : conn{c}, endpoint{e}
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    DatagramIO::DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb) :
            IOChannel{c, e},
            dgram_data_cb{std::move(data_cb)},
            recv_buffer{endpoint._rbufsize},
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

            // TOFIX: reduce below decision tree
            bool oversize = (data.size() > half_size);  // if true, split this packet
            // only split if packet splitting and datagram needs to be split
            if (_packet_splitting && oversize)
            {
                log::trace(log_cat, "Sending oversized datagram...");
                assert(data.size() <= max_size);

                if (_last_dgram_id == 0)  // first pkt
                {
                    _last_dgram_id += 2;
                }
                else if (_last_dgram_id % 4 == 0)  // last datagram was unsplit
                {
                    _last_dgram_id += 6;
                }
                else if (_last_dgram_id % 4 == 3)  // last datagram was split
                {
                    _last_dgram_id += 3;
                }

                // if _skip_next is true, then the last datagram sent was unsplit with an ID that is a
                // perfect multiple of 4. For the next split-datagram, we increment by 6 to get the id
                // for the first of the split-datagrams that satisfies (id % 4) == 2
                //
                // if _skip_next is false, then the last datagram sent was unsplit with an ID that
                // satisfies (id % 4) == 3. For the next split-datagram, we increment by 3 to ge the id
                // for the first of the split-datagrams that satisfies (id % 4) == 2
                // _last_dgram_id += (_skip_next) ? 6 : 3;

                auto first_half = data.substr(0, half_size), second_half = data.substr(half_size);

                std::shared_ptr<void> keep_copy(keep_alive);
                send_buffer.emplace_back(_last_dgram_id, std::make_pair(first_half, std::move(keep_copy)));

                _last_dgram_id += 1;
                send_buffer.emplace_back(_last_dgram_id, std::make_pair(second_half, std::move(keep_alive)));

                _skip_next = false;
            }
            else if (_packet_splitting && not oversize)
            {
                log::trace(log_cat, "Sending standard sized datagram...");

                if (_last_dgram_id % 4 == 0)  // last datagram was unsplit
                {
                    _last_dgram_id += 4;
                }
                else if (_last_dgram_id % 4 == 3)  // last datagram was split
                {
                    _last_dgram_id += 1;
                }

                send_buffer.emplace_back(_last_dgram_id, std::make_pair(data, std::move(keep_alive)));
            }
            else
            {
                log::trace(log_cat, "Sending standard datagram...");
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
            d.bufs[0].base = d.dgid.data();
            d.bufs[0].len = 2;
            d.bufs_len++;
        }

        d.bufs[d.bufs_len - 1].base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(b.second.first.data()));
        d.bufs[d.bufs_len - 1].len = b.second.first.size();

        return d;
    }

    std::optional<bstring> DatagramIO::to_buffer(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "DatagramIO handed datagram with endian swapped ID: {}", dgid);

        auto r = recv_buffer.receive(data, dgid);

        if (r)
            return r;

        return std::nullopt;
    }

    std::optional<bstring> rotating_buffer::receive(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        {
            std::lock_guard<std::mutex> buffer_lock(m);

            auto idx = dgid >> 2;

            row = (idx % bufsize) / rowsize;
            col = idx % rowsize;

            auto& b = buf.at(row).at(col);

            if (not b.empty())
            {
#ifndef NDEBUG
                if (enable_test_features)
                {
                    log::debug(log_cat, "enable_test_features is true, inducing packet loss");
                    test_counter += 1;
                    log::debug(log_cat, "test counter: {}", test_counter);
                    return std::nullopt;
                }
                else
                {
                    log::debug(log_cat, "enable_test_features is false, skipping optional logic");
                }
#endif

                log::trace(log_cat, "Pairing datagram (ID: {}) with counterpart at buffer pos [{},{}]", dgid, row, col);

                bstring out{};
                out.reserve(data.size() + b.data.size());

                bool order = (b.part < 0);  // if true, we have the first part already stored
                // must use substring or we will end up with two datagram ID's at the beginning and middle
                out.append((order ? b.data.substr(2) : data.substr(2)));
                out.append((order ? data.substr(2) : b.data.substr(2)));

                b.clear_entry();

                return out;
            }

            log::trace(log_cat, "Storing datagram (ID: {}) at buffer pos [{},{}]", dgid, row, col);

            b = received_datagram{dgid, data};

            int to_clear = (row + 2) % 4;

            if (to_clear == (last_cleared.load() + 1) % 4)
            {
                clear_row(to_clear);
                last_cleared = to_clear;
            }
        }

        return std::nullopt;
    }

    void rotating_buffer::clear_row(int index)
    {
        // only called by ::receive, which already has a lock_guard in place
        log::trace(log_cat, "Clearing buffer row {} (i = {}, j = {})", index, row.load(), col.load());

        for (auto& b : buf[index])
            b.clear_entry();
    }

    int rotating_buffer::datagrams_stored()
    {
        std::lock_guard<std::mutex> buffer_lock(m);
        log::trace(log_cat, "last_cleared: {}, i: {}, j: {}", last_cleared.load(), row.load(), col.load());

        return (3 - last_cleared.load() + row.load()) * rowsize + col.load();
    }

}  // namespace oxen::quic
