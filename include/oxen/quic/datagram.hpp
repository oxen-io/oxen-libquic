#pragma once

#include "connection_ids.hpp"
#include "iochannel.hpp"
#include "messages.hpp"
#include "utils.hpp"

#include <limits>

namespace oxen::quic
{
    class Connection;
    class Endpoint;
    class Stream;
    class connection_interface;
    struct quic_cid;

    // The pseudo "stream id" we use to indicate the datagram channel:
    inline constexpr int64_t DATAGRAM_PSEUDO_STREAM_ID = std::numeric_limits<int64_t>::min();

    struct dgram_interface : public std::enable_shared_from_this<dgram_interface>
    {
      private:
        connection_interface& ci;

      public:
        dgram_interface(Connection& c);

        const ConnectionID reference_id;

        std::shared_ptr<connection_interface> get_conn_interface();

        template <oxenc::basic_char CharType>
        void reply(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive)
        {
            reply(str_to_bspan(data), std::move(keep_alive));
        }

        template <oxenc::basic_char Char>
        void reply(std::vector<Char>&& buf)
        {
            auto keep_alive = std::make_shared<std::vector<Char>>(std::move(buf));
            auto sp = vec_to_span<std::byte>(*keep_alive);
            reply(sp, std::move(keep_alive));
        }

        template <oxenc::basic_char CharType>
        void reply(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            reply(str_to_bspan(view), std::move(keep_alive));
        }

        void reply(bspan data, std::shared_ptr<void> keep_alive);
    };

    // IO callbacks
    using dgram_data_callback = std::function<void(dgram_interface&, std::vector<std::byte>)>;

    using dgram_buffer = std::deque<std::pair<uint16_t, std::pair<bspan, std::shared_ptr<void>>>>;

    class DatagramIO : public IOChannel
    {

      protected:
        // Construct via net.make_shared<DatagramIO>(...)
        friend class Network;
        friend class Loop;
        DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb = nullptr);

      public:
        dgram_data_callback dgram_data_cb;

        /// Datagram Numbering:
        /// Each datagram ID is comprised of a 16 bit quantity consisting of a 14 bit counter, and
        /// two bits indicating whether the packet is split or not, and, if split, which portion the
        /// associated split packet datagram represents.
        ///
        /// For example,
        ///
        ///     ID: 0bxxxx'xxxx'xxxx'xxzz
        ///                            ^^
        ///               split/nosplit|first or second packet
        ///
        /// Example - unsplit packets:
        ///     Packet Number   |   Packet ID
        ///         1           |       4           In the unsplit packet scheme, the dgram ID of each
        ///         2           |       8           datagram satisfies the rule:
        ///         3           |       12                          (ID % 4) == 0
        ///         4           |       16          As a result, if a dgram ID is received that is a perfect
        ///         5           |       20          multiple of 4, that packet is NOT split
        ///
        /// Example - split packets:
        ///     Packet Number   |   Packet ID
        ///         1                   6           In the split-packet scheme, the dgram ID of the first
        ///         2                   7           of two datagrams satisfies the rule:
        ///         3                   10                          (ID % 4) == 2
        ///         4                   11          The second of the two datagrams satisfies the rule:
        ///         5                   14                          (ID % 4) == 3
        ///         6                   15          As a result, a packet-splitting endpoint should never send
        ///                                         or receive a datagram whose ID is a perfect multiple of 4
        ///
        /// Example - sending split and whole packets:
        ///     Packet Number   |   Packet ID
        ///         1                   6           When sending both split and unsplit packets, the above
        ///         2                   7           numbering is still followed. In the example to the left, the
        ///         3*                  8           unsplit packets are marked with an asterisk(*). An unsplit
        ///         4                   14          packet takes the entire 4-ID block, and the next split packet
        ///         5                   15          begins from the next 4-ID. This way, a receiving endpoint will
        ///         6*                  16          have no confusion on datagram reception when matching split packets
        ///         7                   22          sent intermixed with unsplit packets.
        ///         8                   23
        ///
        uint16_t _next_dgram_counter{0};  // The id *before* shifting the split/side bits

        const int rbufsize;

        /// Holds received datagrams in a rotating "tetris" ring-buffer arrangement of split, unmatched packets.
        /// When a datagram with ID N is recieved, we store it as:
        ///
        ///         tetris_buffer[i][j]
        /// where,
        ///         i = (N % 4096) / 1024
        ///         j = N % 1024
        ///
        /// When it comes to clearing the buffers, the last cleared row is stored in Connection::_last_cleared.
        /// The next row to clear is found as:
        ///
        ///         to_clear = (i + 2) % 4;
        ///         if (to_clear == (last_cleared+1)%4)
        ///         {
        ///             clear(to_clear)
        ///             last_cleared = to_clear
        ///         }
        ///
        /// In full, given 'last_cleared' and a target index 'to_clear', we clear 'to_clear' when 'i' is:
        ///     last_cleared  |  to_clear  |  i
        /// (init) -1               1         3
        ///         0               2         0
        ///         1               3         1
        ///         2               0         2
        ///         3               1         3
        ///
        rotating_buffer recv_buffer;

        std::optional<prepared_datagram> pending_datagram(bool prefer_small) override;
        void confirm_datagram_sent();

        bool is_stream() const override { return false; }

        std::optional<std::vector<std::byte>> to_buffer(bspan data, uint16_t dgid);

        int datagrams_stored() const { return recv_buffer.datagrams_stored(); }

        int64_t stream_id() const override { return DATAGRAM_PSEUDO_STREAM_ID; }

        std::shared_ptr<Stream> get_stream() override;

        // These methods are called during the constructor of the owning Connection to signal if
        // 0-RTT is enabled on the connection, to signal that queued datagrams might not make it and
        // should be stored and retransmitted if 0-RTT is rejected by the server.  The call pattern
        // for any connection is one of:
        //
        // 0-RTT attempted, and succeeded:
        //   - early_data_begin()
        //   - ... datagram activity
        //     - e.g. datagrams delivered by application
        //     - e.g. datagrams consumed by connection for sending out
        //   - early_data_end(true) during handshake complete.
        //
        // 0-RTT not attempted:
        //   - no call to early_data_begin()
        //   - datagrams delivered by application which get queued
        //   - handshake complete (NO call to early_data_end())
        //   - connection starts consuming datagrams for sending out
        //
        // 0-RTT attempted, but rejected:
        //   - early_data_begin()
        //   - ... datagram activity
        //     - e.g. datagrams delivered by application
        //     - e.g. datagrams consumed by connection for sending out
        //   - early_data_end(false) during handshake complete.
        //   - e.g. datagrams consumed by connection for sending out, expecting to start over from
        //     the beginning.
        //
        // It is also possible to get a Retry during the attempt to establish 0-RTT, which signifies
        // that any already-send datagrams are lost and so we mark them all as unsent to try sending
        // them again with the retried 0-RTT connection.
        void early_data_begin();
        void early_data_end(bool accepted);
        void early_data_retry();

        // (See methods of same name in connection_interface for details)
        void set_split_datagram_lookahead(int n);
        int get_split_datagram_lookahead() const;

      private:
        const bool _packet_splitting{false};
        datagram_queue _send_buffer{_packet_splitting};

      protected:
        bool is_empty_impl() const override { return _send_buffer.empty(); }

        void send_impl(bspan data, std::shared_ptr<void> keep_alive) override;

        bool is_closing_impl() const override;
        bool sent_fin() const override;
        void set_fin(bool) override;
        size_t unsent_impl() const override;
        bool has_unsent_impl() const override;
        void wrote(size_t) override;
        std::vector<ngtcp2_vec> pending() override;
    };

}  // namespace oxen::quic
