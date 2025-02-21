#include "messages.hpp"

#include "connection.hpp"
#include "datagram.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

#include <oxenc/endian.h>

#include <limits>

namespace oxen::quic
{
    rotating_buffer::rotating_buffer(DatagramIO& d) : datagram{d}, bufsize{d.rbufsize}, rowsize{d.rbufsize / 4}
    {
        for (auto& v : buf)
            v.resize(rowsize);
    }

    std::optional<std::vector<std::byte>> rotating_buffer::receive(bspan data, uint16_t dgid)
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
                log::debug(log_cat, "enable_datagram_drop_test is false, skipping optional logic");
            }

            log::trace(
                    log_cat,
                    "Pairing datagram (ID: {}) with {} half at buffer pos [{},{}]",
                    dgid,
                    b->first_part ? "first"sv : "second"sv,
                    row,
                    col);

            std::vector<std::byte> out;
            out.reserve(b->data_size + data.size());

            if (b->first_part)
            {
                out.insert(out.end(), b->data.begin(), b->data.begin() + b->data_size);
                out.insert(out.end(), data.begin(), data.end());
            }
            else
            {
                out.insert(out.end(), data.begin(), data.end());
                out.insert(out.end(), b->data.begin(), b->data.begin() + b->data_size);
            }
            b.reset();

            currently_held[row]--;

            return out;
        }

        // Otherwise: new piece
        log::trace(log_cat, "Storing datagram (ID: {}) at buffer pos [{},{}]", dgid, row, col);

        b = std::make_unique<received_datagram>(dgid, data);
        currently_held[row]++;

        int to_clear = (row + 2) % 4;

        if (to_clear == (last_cleared + 1) % 4)
        {
            clear_row(to_clear);
            currently_held[to_clear] = 0;
            last_cleared = to_clear;
        }

        return std::nullopt;
    }

    void datagram_queue::early_data_begin()
    {
        assert(buf.empty());
        early_data_head = std::make_optional<size_t>(0);
    }

    void datagram_queue::early_data_retry()
    {
        if (!early_data_head)
            return;

        // This is the furthest index we could have (partially) marked as sent:
        size_t max_i = *early_data_head + (packet_splitting ? split_lookahead : 0);
        size_t i = 0;
        for (auto& pkt : buf)
        {
            pkt.unsend();
            if (++i > max_i)
                break;
        }
        *early_data_head = 0;
    }

    void datagram_queue::early_data_end(bool accepted)
    {
        if (!early_data_head)
            return;

        if (!accepted)
        {
            // Early data was rejected, which means any 0-RTT datagrams we sent got dropped on
            // the floor and we should unmark them as sent so that they get sent properly under
            // 1-RTT.
            early_data_retry();
        }
        else
        {
            // Early data accepted, so now we can discard all the sent packets (which will be
            // everything up, but not including, `early_data_head`).
            buf.erase(buf.begin(), buf.begin() + *early_data_head);
        }
        early_data_head.reset();
    }

    void datagram_queue::emplace(std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive)
    {
        buf.emplace_back(payload, base_dgid, std::move(keepalive));
    }

    bool datagram_queue::empty() const
    {
        return early_data_head.value_or(0) >= buf.size();
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

    prepared_datagram::prepared_datagram(bool splitting_enabled, uint16_t id, std::span<const std::byte> data) :
            id{id}, bufs_len{1}
    {
        auto vit = bufs.begin();
        if (splitting_enabled)
        {
            bufs_len++;
            oxenc::write_host_as_big(id, dgid.data());
            vit->base = dgid.data();
            vit->len = 2;
            ++vit;
        }
        vit->base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data()));
        vit->len = data.size();
    }

    namespace
    {
        // The two least-significant bits of the dgid indicating whether packet splitting happened.
        // 00 means no splitting, the 0b10 bit means this is a split packet, and the 0b01 bit
        // indicates this is the second part.
        constexpr uint16_t DGID_SPLIT_FIRST = 0b10;
        constexpr uint16_t DGID_SPLIT_SECOND = 0b11;
    }  // namespace

    std::optional<prepared_datagram> datagram_queue::fetch(size_t max_dgram_piece, bool prefer_small)
    {
        log::trace(log_cat, "{} called with ({}, {})", __PRETTY_FUNCTION__, max_dgram_piece, prefer_small);

        if (!buf.empty() && buf.front().unsendable(max_dgram_piece, packet_splitting)) [[unlikely]]
        {
            size_t before = buf.size();
            do
            {
                buf.pop_front();
            } while (!buf.empty() && buf.front().unsendable(max_dgram_piece, packet_splitting));
            log::warning(
                    log_cat,
                    "Dropped {} unsendable datagrams that exceed the max datagram size of {}",
                    before - buf.size(),
                    max_dgram_piece * (packet_splitting ? 2 : 1));
        }

        std::optional<prepared_datagram> result;

        const size_t i = early_data_head.value_or(0);
        if (i >= buf.size())
            return result;

        if (prefer_small && packet_splitting)
        {
            auto it = buf.begin() + i;
            for (size_t off = 0; off <= split_lookahead && it != buf.end(); ++off, ++it)
            {
                auto& dgram = *it;
                if (dgram.sent_second())
                    continue;
                if (i > 0 && dgram.status != DGSent::Unsent)
                    // For non-head lookaheads we can only send the small part if none of the
                    // payload is sent already, because otherwise we would be inducing out-of-order
                    // delivery if we complete the packet before earlier packets.
                    continue;
                std::span<const std::byte> part;
                if (dgram.status == DGSent::SentFirst)
                    // Already partially sent so we return the second part (the first split part is
                    // already away so the split position is now set in stone).
                    part = dgram.payload.subspan(dgram.split_pos);
                else if (dgram.payload.size() > max_dgram_piece)
                    part = dgram.payload.subspan(dgram.split_pos = max_dgram_piece);
                else
                    continue;

                last_i = i + off;
                last_sent = DGSent::SentSecond;
                result.emplace(true, it->base_dgid | DGID_SPLIT_SECOND, part);
                break;
            }
        }

        if (!result)
        {
            // Either we don't want, or we didn't find, a suitable small piece so return the head,
            // preferring the big piece if it needs splitting and we have a choice.
            last_i = i;
            auto& head = buf[i];
            assert(!head.sent());
            if (packet_splitting)
            {
                if (head.status == DGSent::SentFirst)
                {
                    // Already split and first part sent, so we return the predetermined second part.
                    result.emplace(true, head.base_dgid | DGID_SPLIT_SECOND, head.payload.subspan(head.split_pos));
                    last_sent = DGSent::SentSecond;
                }
                else if (head.status == DGSent::SentSecond)
                {
                    // Already split and second part sent, so we return the predetermined first part.
                    result.emplace(true, head.base_dgid | DGID_SPLIT_FIRST, head.payload.subspan(0, head.split_pos));
                    last_sent = DGSent::SentFirst;
                }
                else if (head.size() > max_dgram_piece)
                {
                    // Unsent and needs splitting, so we get to choose the size of the first part.
                    head.split_pos = max_dgram_piece;
                    result.emplace(true, head.base_dgid | DGID_SPLIT_FIRST, head.payload.subspan(0, head.split_pos));
                    last_sent = DGSent::SentFirst;
                }
            }
            if (!result)
            {
                // Splitting disabled, or head doesn't need to be split so we sent the whole thing
                // in one go.
                result.emplace(packet_splitting, head.base_dgid, head.payload);
                last_sent = DGSent::Sent;
            }
        }

        log::trace(
                log_cat,
                "Preparing datagram (id: {}) payload (size: {}): {}",
                result->id,
                result->bufs[result->bufs_len - 1].len,
                buffer_printer{result->bufs[result->bufs_len - 1].base, result->bufs[result->bufs_len - 1].len});
        return result;
    }

    void datagram_queue::confirm_sent()
    {
        assert(last_i < buf.size());
        auto& b = buf[last_i];
        b.status |= last_sent;

        if (b.sent())
        {
            // If this packet is fully sent then it should be the head of the queue; otherwise it
            // means we messed up and sent datagrams out of order.
            assert(last_i == early_data_head.value_or(0));

            if (early_data_head)
                ++*early_data_head;
            else
                buf.pop_front();
        }

        last_i = std::numeric_limits<size_t>::max();
    }

    size_t datagram_queue::pending_bytes() const
    {
        size_t bytes = 0;
        for (auto it = buf.begin() + early_data_head.value_or(0); it != buf.end(); ++it)
            bytes += it->unsent_size();
        return bytes;
    }

    datagram_storage::datagram_storage(
            std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive) :
            base_dgid{base_dgid}, payload{payload}, keep_alive{std::move(keepalive)}
    {}

}  // namespace oxen::quic
