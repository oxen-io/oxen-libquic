#pragma once

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>

#include "context.hpp"
#include "format.hpp"
#include "gnutls_crypto.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    // Wrapper for ngtcp2_cid with helper functionalities to make it passable
    struct alignas(size_t) ConnectionID : ngtcp2_cid
    {
        ConnectionID() = default;
        ConnectionID(const ConnectionID& c) = default;
        ConnectionID(const uint8_t* cid, size_t length);
        ConnectionID(ngtcp2_cid c) : ConnectionID(c.data, c.datalen) {}

        ConnectionID& operator=(const ConnectionID& c) = default;

        inline bool operator==(const ConnectionID& other) const
        {
            return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
        }
        inline bool operator!=(const ConnectionID& other) const { return !(*this == other); }
        static ConnectionID random();

        std::string to_string() const;
    };
    template <>
    constexpr inline bool IsToStringFormattable<ConnectionID> = true;

    class connection_interface
    {
      public:
        virtual std::shared_ptr<Stream> get_new_stream(
                stream_data_callback data_cb = nullptr, stream_close_callback close_cb = nullptr) = 0;

        template <
                typename CharType,
                std::enable_if_t<sizeof(CharType) == 1 && !std::is_same_v<CharType, std::byte>, int> = 0>
        void send_datagram(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive = nullptr)
        {
            send_datagram(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
        void send_datagram(std::vector<Char>&& buf)
        {
            send_datagram(
                    std::basic_string_view<Char>{buf.data(), buf.size()},
                    std::make_shared<std::vector<Char>>(std::move(buf)));
        }

        template <typename CharType>
        void send_datagram(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            send_datagram(view, std::move(keep_alive));
        }

        // TOFIX: We can't template virtual functions; do this a better way if it ends up working
        virtual void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) = 0;

        virtual int get_max_streams() const = 0;
        virtual int get_streams_available() const = 0;
        virtual size_t get_max_datagram_size() const = 0;
        virtual bool datagrams_enabled() const = 0;
        virtual bool packet_splitting_enabled() const = 0;
        virtual Splitting packet_splitting_policy() const = 0;
        virtual const ConnectionID& scid() const = 0;

        virtual ~connection_interface() = default;
    };

    class Connection : public connection_interface, public std::enable_shared_from_this<Connection>
    {
      public:
        // Non-movable/non-copyable; you must always hold a Connection in a shared_ptr
        Connection(const Connection&) = delete;
        Connection& operator=(const Connection&) = delete;
        Connection(Connection&&) = delete;
        Connection& operator=(Connection&&) = delete;

        // Construct and initialize a new inbound/outbound connection to/from a remote
        //      ep: owning endpoints
        //      scid: local ("primary") CID used for this connection (random for outgoing)
        //		dcid: remote CID used for this connection
        //      path: network path used to reach remote client
        //		creds: relevant tls information per connection
        //		u_config: user configuration values passed in struct
        //      dir: enum specifying configuration detailts for client vs. server
        //		hdr: optional parameter to pass to ngtcp2 for server specific details
        static std::shared_ptr<Connection> make_conn(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                ngtcp2_pkt_hd* hdr = nullptr);

        void packet_io_ready();

        const TLSSession* get_session() const { return tls_session.get(); };

        std::shared_ptr<Stream> get_new_stream(
                stream_data_callback data_cb = nullptr, stream_close_callback close_cb = nullptr) override;

        Direction direction() const { return dir; }
        bool is_inbound() const { return dir == Direction::INBOUND; }
        bool is_outbound() const { return dir == Direction::OUTBOUND; }

        bool is_closing() const { return closing; }
        void call_closing();
        bool is_draining() const { return draining; }
        void drain() { draining = true; }

        const ConnectionID& scid() const override { return _source_cid; }
        const ConnectionID& dcid() const { return _dest_cid; }

        const Path& path() const { return _path; }
        const Address& local() const { return _path.local; }
        const Address& remote() const { return _path.remote; }

        Endpoint& endpoint() { return _endpoint; }
        const Endpoint& endpoint() const { return _endpoint; }

        int get_streams_available() const override;
        size_t get_max_datagram_size() const override;
        int get_max_streams() const override { return _max_streams; }
        bool datagrams_enabled() const override { return _datagrams_enabled; }
        bool packet_splitting_enabled() const override { return _packet_splitting; }
        Splitting packet_splitting_policy() const override { return _policy; }

      private:
        // private Constructor (publicly construct via `make_conn` instead, so that we can properly
        // set up the shared_from_this shenanigans).
        Connection(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                ngtcp2_pkt_hd* hdr = nullptr);

        ngtcp2_crypto_conn_ref cref;
        Endpoint& _endpoint;
        std::shared_ptr<IOContext> context;
        Direction dir;
        const ConnectionID _source_cid;
        ConnectionID _dest_cid;
        Path _path;
        std::function<void(Connection&)> on_closing;  // clear immediately after use
        const int _max_streams{DEFAULT_MAX_BIDI_STREAMS};
        const bool _datagrams_enabled{false};
        const bool _packet_splitting{false};
        const Splitting _policy{Splitting::NONE};
        std::atomic<bool> _congested{false};

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
        ///         5           |       20          multiple of 4, that endpoint is NOT splitting packets
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
        uint64_t _increment = 4;
        uint64_t _last_dgram_id{4};
        int _last_cleared{-1};

        // Increments _last_dgram_id by _increment, returns next ID
        uint64_t next_dgram_id();

        // Holds datagrams on deck to be sent
        buffer_que unsent_datagrams;

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
        ///         if (to_clear == (last_cleared+2)%4)
        ///         {
        ///             clear(to_clear)
        ///             last_cleared = to_clear
        ///         }
        ///
        /// In full, given 'last_cleared' and a current tetris_buffer index 'i', we find 'to_clear' to be:
        ///     last_cleared  |  i  |  to_clear
        /// (init) -1                    1
        ///         0                    2
        ///         1                    3
        ///         2                    0
        ///         3                    1
        ///
        std::array<std::array<Packet*, 1024>, 4> tetris_buffer;

        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

        void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        std::shared_ptr<TLSCreds> tls_creds;
        std::unique_ptr<TLSSession> tls_session;

        event_ptr packet_retransmit_timer;
        event_ptr packet_io_trigger;

        void on_packet_io_ready();

        struct pkt_tx_timer_updater;
        bool send(pkt_tx_timer_updater* pkt_updater = nullptr);

        void flush_packets(std::chrono::steady_clock::time_point tp);

        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        uint8_t send_ecn = 0;
        size_t n_packets = 0;

        void schedule_packet_retransmit(std::chrono::steady_clock::time_point ts);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;

        bool draining = false;
        bool closing = false;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // datagram "pseudo-stream"
        std::shared_ptr<DatagramIO> datagrams;
        // "pseudo-stream" to represent ngtcp2 stream ID -1
        std::shared_ptr<Stream> pseudo_stream;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

      public:
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_closed(int64_t id, uint64_t app_code);
        void check_pending_streams(int available);
        int recv_datagram(bstring_view data, bool fin);
        int ack_datagram(uint64_t dgram_id);
        int lost_datagram(uint64_t dgram_id);

        // Implicit conversion of Connection to the underlying ngtcp2_conn* (so that you can pass a
        // Connection directly to ngtcp2 functions taking a ngtcp2_conn* argument).
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator const T*() const
        {
            return conn.get();
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator T*()
        {
            return conn.get();
        }

        // returns number of currently pending streams for use in test cases
        size_t num_pending() const { return pending_streams.size(); }
    };

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref);

        void log_printer(void* user_data, const char* fmt, ...);
    }

}  // namespace oxen::quic

namespace std
{
    // Custom hash is required s.t. unordered_set storing ConnectionID:unique_ptr<Connection>
    // is able to call its implicit constructor
    template <>
    struct hash<oxen::quic::ConnectionID>
    {
        size_t operator()(const oxen::quic::ConnectionID& cid) const
        {
            static_assert(
                    alignof(oxen::quic::ConnectionID) >= alignof(size_t) &&
                    offsetof(oxen::quic::ConnectionID, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };
}  // namespace std
