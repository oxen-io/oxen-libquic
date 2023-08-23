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

#ifdef ENABLE_PERF_TESTING
extern std::atomic<bool> datagram_test_enabled;
#endif

namespace oxen::quic
{
    struct dgram_interface;

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

#ifndef NDEBUG
    class debug_interface
    {
      public:
        std::atomic<bool> datagram_drop_enabled{false};
        std::atomic<int> datagram_drop_counter{0};
        std::atomic<bool> datagram_flip_flop_enabled{false};
        std::atomic<int> datagram_flip_flip_counter{0};
    };
#endif

    class connection_interface : public std::enable_shared_from_this<connection_interface>
    {
      protected:
        virtual std::shared_ptr<Stream> get_new_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) = 0;

      public:
        template <typename StreamT = Stream, typename... Args, std::enable_if_t<std::is_base_of_v<Stream, StreamT>, int> = 0>
        std::shared_ptr<Stream> get_new_stream(Args&&... args)
        {
            return get_new_stream_impl([&](Connection& c, Endpoint& e) {
                return std::make_shared<StreamT>(c, e, std::forward<Args>(args)...);
            });
        }

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

        // note: We can't template virtual functions; do this a better way if it ends up working
        virtual void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) = 0;

        virtual int get_max_streams() const = 0;
        virtual int get_streams_available() const = 0;
        virtual size_t get_max_datagram_size() const = 0;
        virtual bool datagrams_enabled() const = 0;
        virtual bool packet_splitting_enabled() const = 0;
        virtual const ConnectionID& scid() const = 0;

        // WIP functions: these are meant to expose specific aspects of the internal state of connection
        // and the datagram IO object for debugging and application (user) utilization.
        //
        //  datagrams_stored: returns the number of partial datagrams held waiting for their counterpart
        //  last_cleared: returns the index of the last cleared bucket in the recv_buffer
        //  datagram_bufsize: returns the total number of datagrams that the recv_buffer can hold
        virtual int datagrams_stored() const = 0;
        virtual int last_cleared() const = 0;
        virtual int datagram_bufsize() const = 0;

        virtual ~connection_interface() = default;

#ifndef NDEBUG
        debug_interface test_suite;
#endif
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
        //      ctx: IO session dedicated for this connection context
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

        std::shared_ptr<Stream> get_new_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) override;

        Direction direction() const { return dir; }
        bool is_inbound() const { return dir == Direction::INBOUND; }
        bool is_outbound() const { return dir == Direction::OUTBOUND; }

        void halt_events();
        bool is_closing() const { return closing; }
        void set_closing() { closing = true; }
        bool is_draining() const { return draining; }
        void set_draining() { draining = true; }
        void call_close_cb();
        stream_data_callback get_default_data_callback() const;

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

        // public debug functions; to be removed with friend test fixture class
        int datagrams_stored() const override;  // TOFIX: this one
        int last_cleared() const override;
        int datagram_bufsize() const override;

        void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

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
        std::atomic<bool> _congested{false};

        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

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

        std::shared_ptr<Stream> get_stream(int64_t ID) const;

        bool draining = false;
        bool closing = false;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // datagram "pseudo-stream"
        std::unique_ptr<DatagramIO> datagrams;
        // "pseudo-stream" to represent ngtcp2 stream ID -1
        std::shared_ptr<Stream> pseudo_stream;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

        io_result read_packet(const Packet& pkt);

        dgram_interface di;

      public:
        // public to be called by endpoint handing this connection a packet
        void handle_conn_packet(const Packet& pkt);
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_closed(int64_t id, uint64_t app_code);
        void check_pending_streams(int available);
        int recv_datagram(bstring_view data, bool fin);
        int ack_datagram(uint64_t dgram_id);

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
