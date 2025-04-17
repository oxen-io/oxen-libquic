#pragma once

#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace oxen::quic
{
    class DatagramIO;

    struct received_datagram
    {
        uint16_t id{0};
        bool first_part = false;
        uint16_t data_size{0};
        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD> data;

        received_datagram(uint16_t dgid, bspan d) :
                id{dgid}, first_part{dgid % 4 == 2}, data_size{static_cast<uint16_t>(d.size())}
        {
            std::memcpy(data.data(), d.data(), data_size);
        }
    };

    struct rotating_buffer
    {
        int row{0}, col{0}, last_cleared{-1};
        DatagramIO& datagram;
        const int bufsize;
        const int rowsize;
        // tracks the number of partial datagrams held in each buffer bucket
        std::array<int, 4> currently_held{0, 0, 0, 0};

        explicit rotating_buffer() = delete;
        explicit rotating_buffer(DatagramIO& _d);

        std::array<std::vector<std::unique_ptr<received_datagram>>, 4> buf;

        std::optional<std::vector<std::byte>> receive(bspan data, uint16_t dgid);
        void clear_row(int index);
        int datagrams_stored() const;
    };

    enum class dgram { STANDARD = 0, OVERSIZED = 1 };

    struct prepared_datagram
    {
        uint16_t id;                     // both the dgid *and* the internal ID for ngtcp2
        std::array<uint8_t, 2> dgid;     // optional transmitted ID buffer if the conn supports packet splitting
        std::array<ngtcp2_vec, 2> bufs;  // either [dgid, data] or [data], the former if packet
                                         // splitting is enabled.
        size_t bufs_len;                 // 1 for plain [data], 2 for [gdid, data]

        const ngtcp2_vec* data() const { return bufs.data(); }
        size_t size() const { return bufs_len; }

        prepared_datagram(bool splitting_enabled, uint16_t id, std::span<const std::byte> data);
    };

    enum class DGSent : uint8_t {
        Unsent = 0b00,
        SentFirst = 0b01,
        SentSecond = 0b10,
        Sent = SentFirst | SentSecond,
    };
    inline constexpr DGSent operator&(DGSent a, DGSent b)
    {
        return static_cast<DGSent>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
    }
    inline constexpr DGSent operator|(DGSent a, DGSent b)
    {
        return static_cast<DGSent>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
    }
    inline constexpr DGSent operator&=(DGSent& a, DGSent b)
    {
        return a = a & b;
    }
    inline constexpr DGSent operator|=(DGSent& a, DGSent b)
    {
        return a = a | b;
    }

    struct datagram_storage
    {
        // id of the datagram, with the least significant 2 bits unset.  If this datagram is sent
        // unsplit, this id is used as is.  If split then the two LSBs will be set to 0b10 for the
        // first part and 0b11 for the second part.
        uint16_t base_dgid;
        DGSent status = DGSent::Unsent;
        // If status is not Unsent, split_pos contains the divider position between big first part
        // and small second part.
        uint16_t split_pos = std::numeric_limits<uint16_t>::max();
        std::span<const std::byte> payload;
        std::shared_ptr<void> keep_alive;

        datagram_storage(std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive);

        // True if the packet is fully sent.  (I.e. sent unsplit packet, or split packet with both
        // parts sent).
        constexpr bool sent() const { return status == DGSent::Sent; }
        // True if entirely sent (splitting or otherwise) *or* if the first part is sent
        constexpr bool sent_first() const { return (status & DGSent::SentFirst) == DGSent::SentFirst; }
        // True if entirely sent (splitting or otherwise) *or* if the second part is sent
        constexpr bool sent_second() const { return (status & DGSent::SentSecond) == DGSent::SentSecond; }

        constexpr size_t size() const { return payload.size(); }

        // Returns the size of any unsent data.  Does not include the dgid prefix overhead of split
        // packets.
        constexpr uint16_t unsent_size() const
        {
            switch (status)
            {
                case DGSent::Sent:
                    return 0;
                case DGSent::SentFirst:
                    return payload.size() - split_pos;
                case DGSent::SentSecond:
                    return split_pos;
                case DGSent::Unsent:
                    return payload.size();
            }
            assert(false);
            return 0;
        }

        // Returns true if this datagram is not sendable under the given max application datagram
        // piece size (which already accounts for the 2 byte overhead when splitting is enabled, but
        // is *not* the doubled max split size).  Used to detect datagrams that need to be dropped
        // in case a PMTU decrease left unsendable queued packets.
        constexpr bool unsendable(size_t max_dgram_piece, bool packet_splitting) const
        {
            switch (status)
            {
                case DGSent::Sent:
                    return false;
                case DGSent::Unsent:
                    return payload.size() > max_dgram_piece * (packet_splitting ? 2 : 1);
                case DGSent::SentFirst:
                    return (payload.size() - split_pos) > max_dgram_piece;
                case DGSent::SentSecond:
                    return split_pos > max_dgram_piece;
            }
            assert(false);
            return true;
        }

        // Used at the end of 0-RTT if early data is rejected to unmark a packet as sent so that it
        // will be resent under 1-RTT.
        void unsend() { status = DGSent::Unsent; }
    };

    struct datagram_queue
    {
        // Default lookahead.  (If changing this remember to also update the documentation in
        // connection.hpp).
        static constexpr size_t DEFAULT_SPLIT_LOOKAHEAD = 8;

        datagram_queue(bool packet_splitting) : packet_splitting{packet_splitting} {}

        // Call to start early data.  Should be called (if at all) during Connection setup, before
        // any datagrams can actually be delivered to the queue.
        void early_data_begin();

        // Called to retry all datagrams by marking them as unsent; this is called by early_data_end
        // if early data was rejected, but is also called if we receive a Retry packet from the
        // server during 0-RTT, which means any already-send 0-RTT datagrams will have been lost and
        // need to be retransmitted.
        void early_data_retry();

        // Called as soon as early data is finished, if initiailized in early data mode (i.e.
        // attempting 0-RTT).  That is, it is called as soon as early data is rejected, or as soon
        // as handshake completes without early data rejection.  The bool indicates whether early
        // data was accepted or rejected; if rejected, we reset the sent status of any queued
        // datagrams so that they will be sent again.  If accepted, we drop any fully sent
        // datagrams.  It doesn't hurt to call this multiple times; only the first call does
        // anything.
        void early_data_end(bool accepted);

        // Fetches the next datagram or datagram piece to be sent.
        //
        // `max_dgram_piece` will be used for two purposes:
        // - first to discard any leading packets that can no longer be sent.  This is somewhat
        //   rare, as it would mean the packet was acceptable when it was created, but then PMTU
        //   decreased.  Without this, however, such a decrease would result in a head-blocking,
        //   unsendable packet.
        // - second to determine whether we need to split packets, and if so, how large the first
        //   part of the split should be (with the remainder going to the "small" piece described
        //   below).
        //
        // `prefer_small` controls how we return small packet pieces when the head-of-the-queue
        // packet is itself a split packet.  If true, this hints that the connection has already
        // partially filled a QUIC packet and is looking to potentially add more into it, in which
        // case a "large" split packet piece will most likely not fit, and that we should look for a
        // small piece that might.  Specifically, when this flag is set, we look for any unsent
        // smaller packet piece in the next `split_lookahead` packets where the large piece has not
        // yet been sent, and returns the first one found.  (If no such packet is found, we return
        // the first unset packet, even if it is big).  Note that we never return a small piece
        // where the big piece *has* been sent, nor do we return an unsplit, non-head-of-the-list
        // datagram because either of those would result in us deliberately causing out-or-order
        // (reassembled) datagram delivery on the remote.  When the head of the queue packet is
        // itself unsplit, we always return that packet, regardless of the prefer_small setting,
        // because such a packet may fit in whatever is available in the ngtcp2 packet being
        // constructed.
        //
        // When `prefer_small` is false, we always return the datagram at the head of the queue; if
        // we have a choice (i.e. the head is split with neither part sent) then we prefer the large
        // piece, but otherwise return the unsent part of a split packet, or the whole (unsplit)
        // packet that is next awaiting sending.
        //
        // In effect, this fetching allows batching several small pieces together, allowing
        // transmission in fewer packets.  For example: suppose we have a continuous queue of split
        // packets, [Aa] [Bb] [Cc] ...  With the hint and lookahead we can send these datagrams
        // using the following patterns for different lookahead values (where the ... indicates
        // where the pattern starts repeating), assuming that all the small abc... datagram pieces
        // are sufficiently small to get packed into a single quic packet:
        //
        // 5: [A] [abcdefg] [B] [C] [D] [E] [F] [G] ...  -- 8 quic packets per 7 split datagrams
        // 4: [A] [abcdef] [B] [C] [D] [E] [F] ...  -- 7 quic packets per 6 split datagrams
        // 3: [A] [abcde] [B] [C] [D] [E] ...  -- 6 quic packets per 5 split datagrams
        // 2: [A] [abcd] [B] [C] [D] ...  -- 5 quic packets per 4 split datagrams
        // 1: [A] [abc] [B] [C] ...  -- 4 quic packets per 3 split datagrams
        // 0: [A] [ab] [B] ... -- 3 quic packets per 2 split datagrams
        //
        // (The reason that with n lookahead we can include n+2 small pieces is that in each case
        // the `b` inclusion is not a lookahead: once `a` has been accepted, `b` is not a lookahead
        // value, because including `a` completed the `[Aa]` datagram and so when `b` is considered
        // for inclusion the `[Bb]` packet is the head of the queue, and so only `c...` in the
        // examples are out-of-order lookaheads.)
        //
        // None of this has any effect if split datagrams are not enabled.
        //
        // If this returns a datagram, and that datagram is accepted for sending, then the sending
        // code must immediately call confirm_sent() to properly update the status and/or clean up
        // the just-sent packet.
        std::optional<prepared_datagram> fetch(size_t max_dgram_size, bool prefer_small);

        // See comment above.
        size_t split_lookahead = DEFAULT_SPLIT_LOOKAHEAD;

        // This must be called immediately after the previous fetch() to indicate that the result
        // returned by fetch has been sent and should be marked as such.  If the confirmation
        // completes a packet (and we are not in early data mode) then the datagram is dropped.  If
        // the datagram fails to send then don't call anything; the next fetch() resets state.
        void confirm_sent();

        void emplace(std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive);

        // Returns true if the queue is empty (not counting already-sent early data, if still in the
        // early data period).
        bool empty() const;

        // Returns the number of unsent datagrams.  (Note: this counts input datagrams, i.e. split
        // datagrams are counted as one).
        size_t size() const { return buf.size() - early_data_head.value_or(0); }

        // Returns the number of unsent bytes of all pending datagrams.  For split datagrams, the
        // count is the size of any unsent pieces, i.e. half-sent split datagrams only count the
        // bytes in the remaining, unsent piece.  Note also that this only includes the raw datagram
        // size, but not the dgid prefix that is prepended to all datagrams when in split datagram
        // mode.
        size_t pending_bytes() const;

      private:
        const bool packet_splitting;
        std::optional<size_t> early_data_head;
        size_t last_i = std::numeric_limits<size_t>::max();
        DGSent last_sent = DGSent::Unsent;

        std::deque<datagram_storage> buf{};
    };

}  // namespace oxen::quic
