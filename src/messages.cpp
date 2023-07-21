#include "messages.hpp"

#include "connection.hpp"
#include "datagram.hpp"

namespace oxen::quic
{
    Packet::Packet(const Address& local, bstring_view data, msghdr& hdr) :
            path{local,
#ifdef _WIN32
                 {static_cast<const sockaddr*>(hdr.name), hdr.namelen}
#else
                 {static_cast<const sockaddr*>(hdr.msg_name), hdr.msg_namelen}
#endif
            },
            data{data}
    {
        // ECN flag:
        assert(path.remote.is_ipv4() || path.remote.is_ipv6());
#ifdef _WIN32
        for (auto cmsg = WSA_CMSG_FIRSTHDR(&hdr); cmsg; cmsg = WSA_CMSG_NXTHDR(&hdr, cmsg))
        {
            if ((path.remote.is_ipv4() ? (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ECN)
                                       : (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_ECN)) &&
                cmsg->cmsg_len > 0)
            {
                pkt_info.ecn = *reinterpret_cast<uint8_t*>(WSA_CMSG_DATA(cmsg));
                break;
            }
        }
#else
        for (auto cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg))
        {
            if ((path.remote.is_ipv4() ? (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
                                       : (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) &&
                cmsg->cmsg_len > 0)
            {
                pkt_info.ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg));
                break;
            }
        }
#endif
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
            if (d.conn.enable_datagram_drop_test)
            {
                log::debug(log_cat, "enable_datagram_drop_test is true, inducing packet loss");
                d.conn.test_drop_counter += 1;
                log::debug(log_cat, "test counter: {}", d.conn.test_drop_counter.load());
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
