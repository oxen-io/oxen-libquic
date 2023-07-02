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

#include "types.hpp"
#include "format.hpp"
#include "context.hpp"
#include "gnutls_crypto.hpp"
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

        virtual int get_max_streams() const = 0;
        virtual int get_streams_available() const = 0;

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

        void io_ready();

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

      private:
        std::shared_ptr<IOContext> context;
        user_config uconfig;
        Direction dir;
        Endpoint& _endpoint;
        const ConnectionID _source_cid;
        ConnectionID _dest_cid;
        Path _path;
        std::function<void(Connection&)> on_closing;  // clear immediately after use

        // private Constructor (publicly construct via `make_conn` instead, so that we can properly
        // set up the shared_from_this shenanigans).
        Connection(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                ngtcp2_pkt_hd* hdr = nullptr);

        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

        void setup_tls_session(bool is_client);

        int get_max_streams() const override
        { return uconfig.max_streams; }
        int get_streams_available() const override;

        std::shared_ptr<TLSCreds> tls_creds;
        std::unique_ptr<TLSSession> tls_session;

        event_ptr retransmit_timer;
        event_ptr io_trigger;

        void on_io_ready();

        struct pkt_tx_timer_updater;
        bool send(pkt_tx_timer_updater* pkt_updater = nullptr);

        void flush_streams(std::chrono::steady_clock::time_point tp);

        std::array<std::byte, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        uint8_t send_ecn = 0;
        size_t n_packets = 0;

        void schedule_retransmit(std::chrono::steady_clock::time_point ts);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;


        bool draining = false;
        bool closing = false;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

      public:
        // Buffer used to store non-stream connection data
        //  ex: initial transport params
        bstring conn_buffer;
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_closed(int64_t id, uint64_t app_code);
        void check_pending_streams(int available);

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
