#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"

#ifndef NDEBUG
std::atomic<bool> oxen::quic::enable_datagram_drop_test;
std::atomic<bool> oxen::quic::enable_datagram_flip_flop_test;
std::atomic<int> oxen::quic::test_counter;
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

#ifndef NDEBUG
        if (enable_datagram_flip_flop_test)
        {
            log::debug(log_cat, "enable_datagram_flip_flop_test is true, bypassing buffer");
            test_counter += 1;
            log::debug(log_cat, "test counter: {}", test_counter.load());
            return std::nullopt;
        }
        else
        {
            log::debug(log_cat, "enable_datagram_flip_flop_test is false, skipping optional logic");
        }

#endif

        return recv_buffer.receive(data, dgid);
    }

    std::optional<bstring> rotating_buffer::receive(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        auto idx = dgid >> 2;

        row = (idx % bufsize) / rowsize;
        col = idx % rowsize;

        auto& b = buf[row][col];

        if (not b.empty())
        {
#ifndef NDEBUG
            if (enable_datagram_drop_test)
            {
                log::debug(log_cat, "enable_datagram_drop_test is true, inducing packet loss");
                test_counter += 1;
                log::debug(log_cat, "test counter: {}", test_counter.load());
                return std::nullopt;
            }
            else
            {
                log::debug(log_cat, "enable_datagram_drop_test is false, skipping optional logic");
            }
#endif

            log::trace(
                    log_cat,
                    "Pairing datagram (ID: {}) with {} half at buffer pos [{},{}]",
                    dgid,
                    (b.part < 0 ? "first"s : "second"s),
                    row,
                    col);

            if (b.part < 0)  // if true, we have the first part already stored
                b.data.append(data);
            else
            {
                b.data.reserve(b.data.size() + data.size());
                b.data.insert(0, data.data());
            }

            bstring out{std::move(b.data)};

            b.clear_entry();

            return out;
        }

        log::trace(log_cat, "Storing datagram (ID: {}) at buffer pos [{},{}]", dgid, row, col);

        b = received_datagram{dgid, data};

        int to_clear = (row + 2) % 4;

        if (to_clear == (last_cleared + 1) % 4)
        {
            clear_row(to_clear);
            last_cleared = to_clear;
        }

        return std::nullopt;
    }

    void buffer_que::emplace(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data, dgram type, size_t max_size)
    {
        auto d_storage = datagram_storage::make(pload, p_id, std::move(data), type, max_size);

        buf.push_back(std::move(d_storage));
    }

    void buffer_que::drop_front(std::atomic<bool>& b)
    {
        auto& f = buf.front();

        if (f.type == dgram::STANDARD)
        {
            f.payload.reset();
            buf.pop_front();
            return;
        }

        if (f.payload && not f.addendum)
            f.payload.reset();
        else if (f.addendum && not f.payload)
            f.addendum.reset();
        else
        {
            (b ? f.payload : f.addendum).reset();
            return;
        }

        assert(f.empty());
        buf.pop_front();
    }

    void rotating_buffer::clear_row(int index)
    {
        log::trace(log_cat, "Clearing buffer row {} (i = {}, j = {})", index, row, col);

        for (auto& b : buf[index])
            b.clear_entry();
    }

    int rotating_buffer::datagrams_stored()
    {
        log::trace(log_cat, "last_cleared: {}, i: {}, j: {}", last_cleared, row, col);

        return (3 - last_cleared + row) * rowsize + col;
    }

    outbound_dgram datagram_storage::fetch(std::atomic<bool>& b)
    {
        if (type == dgram::STANDARD)
            return {*payload, pload_id, -1, true};

        if (payload && not addendum)
            return {*payload, pload_id, -1, true};
        else if (addendum && not payload)
            return {*addendum, *add_id, 1, true};
        else
            return {(b ? *payload : *addendum), (b ? pload_id : *add_id), (b ? -1 : 1), false};
    }

    prepared_datagram buffer_que::prepare(std::atomic<bool>& b, int is_splitting)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        prepared_datagram d{};

        outbound_dgram out = buf.front().fetch(b);
        d.id = out.id;
        d.bufs_len = 1;
        d.is_empty = out.is_empty;

        oxenc::write_host_as_big(out.id, d.dgid.data());

        if (is_splitting)
        {
            d.bufs[0].base = d.dgid.data();
            d.bufs[0].len = 2;
            d.bufs_len++;
        }

        d.bufs[d.bufs_len - 1].base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(out.data.data()));
        d.bufs[d.bufs_len - 1].len = out.data.size();

        log::trace(
                log_cat,
                "Preparing datagram (id: {}) payload (size: {}): {}",
                out.id,
                out.data.size(),
                buffer_printer{out.data});

        for (size_t i = 0; i < d.bufs_len; ++i)
        {
            log::trace(log_cat, "Checking index {}", i);
            assert(d.bufs[i].len);
        }

        return d;
    }

    datagram_storage datagram_storage::make(
            bstring_view pload, uint16_t d_id, std::shared_ptr<void> data, dgram type, size_t max_size)
    {
        if (type == dgram::STANDARD)
            return datagram_storage(pload, d_id, std::move(data));

        assert(max_size != 0);

        auto half_size = max_size / 2;
        auto first_half = pload.substr(0, half_size), second_half = pload.substr(half_size);

        assert(d_id % 4 == 2);

        return datagram_storage(first_half, second_half, d_id, d_id + 1, std::move(data));
    }
}  // namespace oxen::quic
