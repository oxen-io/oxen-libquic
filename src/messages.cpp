#include "messages.hpp"

#include "connection.hpp"
#include "datagram.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

namespace oxen::quic
{
    rotating_buffer::rotating_buffer(DatagramIO& d) : datagram{d}, bufsize{d.rbufsize}, rowsize{d.rbufsize / 4}
    {
        for (auto& v : buf)
            v.resize(rowsize);
    }

    std::optional<bstring> rotating_buffer::receive(bstring_view data, uint16_t dgid)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        assert(datagram.endpoint.in_event_loop());
        assert(datagram._conn);

        auto idx = dgid >> 2;
        log::trace(
                log_cat,
                "dgid: {}, row: {}, col: {}, idx: {}, rowsize: {}, bufsize {}",
                dgid,
                row,
                col,
                idx,
                rowsize,
                bufsize);

        row = (idx % bufsize) / rowsize;
        col = idx % rowsize;

        auto& b = buf[row][col];

        if (b)
        {
            if (datagram._conn->debug_datagram_drop_enabled)
            {
                log::debug(log_cat, "enable_datagram_drop_test is true, inducing packet loss");
                datagram._conn->debug_datagram_counter++;
                log::debug(log_cat, "test counter: {}", datagram._conn->debug_datagram_counter);
                return std::nullopt;
            }
            else
            {
                log::trace(log_cat, "enable_datagram_drop_test is false, skipping optional logic");
            }

            log::trace(
                    log_cat,
                    "Pairing datagram (ID: {}) with {} half at buffer pos [{},{}]",
                    dgid,
                    (b->part < 0 ? "first"s : "second"s),
                    row,
                    col);

            bstring out;
            out.reserve(b->data_size + data.size());
            if (b->part < 0)
            {  // We have the first part already
                out.append(b->data.data(), b->data_size);
                out.append(data);
            }
            else
            {
                out.append(data);
                out.append(b->data.data(), b->data_size);
            }
            b.reset();

            currently_held[row] -= 1;

            return out;
        }

        // Otherwise: new piece
        log::trace(log_cat, "Storing datagram (ID: {}) at buffer pos [{},{}]", dgid, row, col);

        b = std::make_unique<received_datagram>(dgid, data);
        currently_held[row] += 1;

        int to_clear = (row + 2) % 4;

        if (to_clear == (last_cleared + 1) % 4)
        {
            clear_row(to_clear);
            currently_held[to_clear] = 0;
            last_cleared = to_clear;
        }

        return std::nullopt;
    }

    void buffer_que::emplace(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data, dgram type, size_t max_size)
    {
        auto d_storage = datagram_storage::make(pload, p_id, std::move(data), type, max_size);

        buf.push_back(std::move(d_storage));
    }

    void buffer_que::drop_front(bool b)
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
            if (b)
                b.reset();
    }

    int rotating_buffer::datagrams_stored() const
    {
        return std::accumulate(currently_held.begin(), currently_held.end(), 0);
    }

    outbound_dgram datagram_storage::fetch(bool b)
    {
        if (type == dgram::STANDARD)
            return {*payload, pload_id, -1, true};

        if (payload && not addendum)
            return {*payload, pload_id, -1, true};
        else if (addendum && not payload)
            return {*addendum, *add_id, 1, true};
        else if (b)
            return {*payload, pload_id, -1, false};
        else
            return {*addendum, *add_id, 1, false};
    }

    prepared_datagram buffer_que::prepare(bool b, int is_splitting)
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
