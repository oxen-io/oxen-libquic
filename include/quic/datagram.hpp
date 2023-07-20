#pragma once

#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
#ifndef NDEBUG
    extern std::atomic<bool> enable_datagram_drop_test;
    extern std::atomic<bool> enable_datagram_flip_flop_test;
    extern std::atomic<int> test_counter;
#endif

    class IOChannel;
    class Connection;
    class Endpoint;
    class Stream;

    // IO callbacks
    using dgram_data_callback = std::function<void(bstring)>;

    using dgram_buffer = std::deque<std::pair<uint16_t, std::pair<bstring_view, std::shared_ptr<void>>>>;

    enum class dgram { STANDARD = 0, OVERSIZED = 1 };

    struct outbound_dgram
    {
        bstring_view data;
        uint16_t id;
        // -1: payload, 1: addendum
        int type{0};
        // is the datagram_storage container empty after sending this payload?
        bool is_empty{false};

        outbound_dgram() = default;
    };

    struct prepared_datagram
    {
        uint64_t id;                  // internal ID for ngtcp2
        std::array<uint8_t, 2> dgid;  // optional transmitted ID buffer (for packet splitting)
        std::array<ngtcp2_vec, 2> bufs;
        size_t bufs_len;  // either 1 or 2 depending on how much of data is populated
        // is the datagram_storage container empty after sending this payload?
        bool is_empty{false};

        const ngtcp2_vec* data() const { return bufs.data(); }
        size_t size() const { return bufs_len; }
    };

    struct received_datagram
    {
        uint16_t id{0};
        // -1 = payload, 1 = addendum
        int part{0};
        bstring data{};

        received_datagram() = default;
        explicit received_datagram(uint16_t dgid, bstring_view d) : id{dgid}, part{(dgid % 4 == 2) ? -1 : 1}
        {
            data.reserve(d.size() + MAX_PMTUD_UDP_PAYLOAD);
            data.append(d);
        };

        void clear_entry()
        {
            id = 0;
            part = 0;
            data.clear();
        };

        bool empty() const { return data.empty() && part == 0; }
    };

    struct datagram_storage
    {
        uint16_t pload_id;
        std::optional<uint16_t> add_id;
        std::optional<bstring_view> payload, addendum;
        std::shared_ptr<void> keep_alive;
        dgram type;

        static datagram_storage make(
                bstring_view pload, uint16_t d_id, std::shared_ptr<void> data, dgram type, size_t max_size = 0);

        bool empty() const { return !(payload || addendum); }

        outbound_dgram fetch(std::atomic<bool>& b);

        size_t size() const { return payload->length() + addendum->length(); }

      private:
        explicit datagram_storage(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data) :
                pload_id{p_id}, payload{pload}, keep_alive{std::move(data)}, type{dgram::STANDARD}
        {}

        explicit datagram_storage(
                bstring_view pload, bstring_view add, uint16_t p_id, uint16_t a_id, std::shared_ptr<void> data) :
                pload_id{p_id},
                add_id{a_id},
                payload{pload},
                addendum{add},
                keep_alive{std::move(data)},
                type{dgram::OVERSIZED}
        {}
    };

    struct rotating_buffer
    {
        int row{0}, col{0}, last_cleared{-1};
        const int bufsize{4096};
        const int rowsize{bufsize / 4};

        rotating_buffer() = default;
        explicit rotating_buffer(int b) : bufsize{b} {};

        std::vector<std::vector<received_datagram>> buf{4, std::vector<received_datagram>(rowsize)};

        std::optional<bstring> receive(bstring_view data, uint16_t dgid);
        void clear_row(int index);
        int datagrams_stored();
    };

    struct buffer_que
    {
        std::deque<datagram_storage> buf{};
        size_t quantity{0};

        bool empty() const { return buf.empty(); }
        size_t size() const { return quantity; }

        void drop_front(std::atomic<bool>& b);

        prepared_datagram prepare(std::atomic<bool>& b, int is_splitting);

        void emplace(bstring_view pload, uint16_t p_id, std::shared_ptr<void> data, dgram type, size_t max_size = 0);
    };

    class IOChannel
    {
      public:
        IOChannel(Connection& c, Endpoint& e);

        virtual ~IOChannel() { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };

        Connection& conn;
        Endpoint& endpoint;

        // no copy, no move. always hold in a shared pointer
        IOChannel(const IOChannel&) = delete;
        IOChannel& operator=(const IOChannel&) = delete;
        IOChannel(IOChannel&&) = delete;
        IOChannel& operator=(IOChannel&&) = delete;

        virtual bool is_stream() = 0;
        virtual bool is_empty() const = 0;
        virtual std::shared_ptr<Stream> get_stream() = 0;
        virtual void send(bstring_view, std::shared_ptr<void> keep_alive = nullptr) = 0;
        virtual std::vector<ngtcp2_vec> pending() = 0;
        virtual prepared_datagram pending_datagram(std::atomic<bool>&) = 0;
        virtual int64_t stream_id() const = 0;
        virtual bool is_closing() const = 0;
        virtual bool sent_fin() const = 0;
        virtual void set_fin(bool) = 0;
        virtual size_t unsent() const = 0;
        virtual void wrote(size_t) = 0;
        virtual bool has_unsent() const = 0;
    };

    class DatagramIO : public IOChannel
    {
      public:
        DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb = nullptr);
        dgram_data_callback dgram_data_cb;

        /// Datagram Numbering:
        /// Each datagram ID is incremented by four from the previous one, regardless of whether we are
        /// splitting packets. The first 12 MSBs are the counter, and the 2 LSBs indicate if the packet
        /// is split or not and which it is in the split (respectively). For example,
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
        uint16_t _last_dgram_id{0};

        // used to track if just sent an unsplit packet and need to increment by an extra 4 to send a split packet
        bool _skip_next{false};  // TOFIX: do i even use this?!

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
        // dgram_buffer send_buffer;
        buffer_que send_buffer;

        bool is_empty() const override { return send_buffer.empty(); }

        void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        prepared_datagram pending_datagram(std::atomic<bool>& r) override;

        bool is_stream() override { return false; }

        std::optional<bstring> to_buffer(bstring_view data, uint16_t dgid);

        int datagrams_stored() { return recv_buffer.datagrams_stored(); };

      private:
        const bool _packet_splitting{false};

        std::shared_ptr<Stream> get_stream() override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return nullptr;
        };
        int64_t stream_id() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return std::numeric_limits<int64_t>::min();
        };
        bool is_closing() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        bool sent_fin() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        void set_fin(bool) override { log::debug(log_cat, "{} called", __PRETTY_FUNCTION__); };
        size_t unsent() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            size_t sum{0};
            if (send_buffer.empty())
                return sum;
            for (const auto& entry : send_buffer.buf)
                sum += entry.size();
            return sum;
        };
        bool has_unsent() const override { return not is_empty(); }
        void wrote(size_t) override { log::debug(log_cat, "{} called", __PRETTY_FUNCTION__); };
        std::vector<ngtcp2_vec> pending() override
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            return std::vector<ngtcp2_vec>{};
        };
    };
}  // namespace oxen::quic

/*

Revolving send buffer:
    - both datagram halves have the same right shifted index

Receive buffer:
    - more rows can increase tolerance in misordering
    - too many short ones leads to pinstriping

*/
