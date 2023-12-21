#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>

#include "context.hpp"
#include "format.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    struct dgram_interface;
    class Network;

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
        virtual std::shared_ptr<Stream> queue_incoming_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) = 0;
        virtual std::shared_ptr<Stream> open_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) = 0;
        virtual std::shared_ptr<Stream> get_stream_impl(int64_t id) = 0;

      public:
        virtual ustring_view selected_alpn() const = 0;

        /// Queues an incoming stream of the given StreamT type, forwarding the given arguments to
        /// the StreamT constructor.  The stream will be given the next unseen incoming connection
        /// ID; it will be made ready once the associated stream id is seen from the remote
        /// connection.  Note that this constructor bypasses the stream constructor callback for the
        /// applicable stream id.
        template <
                typename StreamT,
                typename... Args,
                typename EndpointDeferred = Endpoint,
                std::enable_if_t<std::is_base_of_v<Stream, StreamT>, int> = 0>
        std::shared_ptr<StreamT> queue_incoming_stream(Args&&... args)
        {
            // We defer resolution of `Endpoint` here via `EndpointDeferred` because the header only
            // has a forward declaration; the user of this method needs to have the full definition
            // available to call this.
            return std::static_pointer_cast<StreamT>(queue_incoming_stream_impl([&](Connection& c, EndpointDeferred& e) {
                return e.template make_shared<StreamT>(c, e, std::forward<Args>(args)...);
            }));
        }

        /// Queues a default incoming Stream object, either via the stream constructor callback (if
        /// set) or the default Stream constructor (if no constructor callback, or the callback
        /// returns nullptr).  The stream object will be made ready once the associated next
        /// incoming stream ID is observed from the other end.
        std::shared_ptr<Stream> queue_incoming_stream();

        /// Opens a new outgoing stream to the other end of the connection of the given StreamT
        /// type, forwarding the given arguments to the StreamT constructor.  The returned stream
        /// may or may not be ready (and have an id assigned) based on whether there are available
        /// stream ids on the connection.  Check `->ready` on the returned instance to check.  If
        /// not ready the stream will be queued and become ready once a stream id becomes available,
        /// such as from an increase in available stream ids resulting from the closure of an
        /// existing stream.  Note that this constructor bypasses the stream constructor callback
        /// for the applicable stream id.
        template <
                typename StreamT,
                typename... Args,
                typename EndpointDeferred = Endpoint,
                std::enable_if_t<std::is_base_of_v<Stream, StreamT>, int> = 0>
        std::shared_ptr<StreamT> open_stream(Args&&... args)
        {
            return std::static_pointer_cast<StreamT>(open_stream_impl([&](Connection& c, EndpointDeferred& e) {
                return e.template make_shared<StreamT>(c, e, std::forward<Args>(args)...);
            }));
        }

        /// Opens a bog standard Stream connection to the other end of the connection.  This version
        /// of open_stream takes no arguments; it will invoke the stream constructor callback (if
        /// configured) and otherwise will fall back to construct a default Stream.  See the
        /// comments in the templated version of the method, above, for details about the readiness
        /// of the returned stream.
        std::shared_ptr<Stream> open_stream();

        /// Returns a stream object for the stream with the given id, if the stream exists (and, if
        /// StreamT is specified, is of the given Stream subclass).  Returns nullptr if the id is
        /// not currently an open stream; throws std::invalid_argument if the stream exists but is
        /// not an instance of the given StreamT type.
        template <typename StreamT = Stream, std::enable_if_t<std::is_base_of_v<Stream, StreamT>, int> = 0>
        std::shared_ptr<StreamT> maybe_stream(int64_t id)
        {
            auto s = get_stream_impl(id);
            if (!s)
                return nullptr;
            if constexpr (!std::is_same_v<StreamT, Stream>)
            {
                if (auto st = std::dynamic_pointer_cast<StreamT>(std::move(s)))
                    return st;
                throw std::invalid_argument{"Stream ID {} is not an instance of the requested Stream subclass"_format(id)};
            }
            else
                return s;
        }

        /// Returns a stream object for the stream with the given id, if the stream exists (and, if
        /// StreamT is specified, is of the given Stream subclass).  Otherwise throws
        /// std::out_of_range if the stream was not found, and std::invalid_argument if the stream
        /// was found, but is not an instance of StreamT.
        template <typename StreamT = Stream, std::enable_if_t<std::is_base_of_v<Stream, StreamT>, int> = 0>
        std::shared_ptr<StreamT> get_stream(int64_t id)
        {
            if (auto s = maybe_stream<StreamT>(id))
                return s;
            throw std::out_of_range{"Could not find a stream with ID {}"_format(id)};
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

        virtual void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) = 0;
        virtual size_t active_streams() const = 0;
        virtual uint64_t get_max_streams() const = 0;
        virtual uint64_t get_streams_available() const = 0;
        virtual size_t get_max_datagram_size() const = 0;
        virtual bool datagrams_enabled() const = 0;
        virtual bool packet_splitting_enabled() const = 0;
        virtual const ConnectionID& scid() const = 0;
        virtual const Address& local() const = 0;
        virtual const Address& remote() const = 0;
        virtual bool is_validated() const = 0;
        virtual Direction direction() const = 0;
        virtual ustring_view remote_key() const = 0;
        bool is_inbound() const { return direction() == Direction::INBOUND; }
        bool is_outbound() const { return direction() == Direction::OUTBOUND; }
        std::string_view direction_str() const { return direction() == Direction::INBOUND ? "server"sv : "client"sv; }

        // WIP functions: these are meant to expose specific aspects of the internal state of connection
        // and the datagram IO object for debugging and application (user) utilization.
        //
        //  last_cleared: returns the index of the last cleared bucket in the recv_buffer
        virtual int last_cleared() const = 0;

        virtual void close_connection(uint64_t error_code = 0) = 0;

#ifndef NDEBUG
        virtual ~connection_interface();

        debug_interface test_suite;
#else
        virtual ~connection_interface() = default;
#endif
    };

    class Connection : public connection_interface
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
        //      alpns: passed directly to TLS session for handshake negotiation. The server
        //          will select the first in the client's list it also supports, so the user
        //          should list them in decreasing priority. If the user does not specify alpns,
        //          the default will be set
        //      remote_pk: optional parameter used by clients to verify the pubkey of the remote
        //          endpoint during handshake negotiation. For servers, omit this parameter or
        //          pass std::nullopt
        //		hdr: optional parameter to pass to ngtcp2 for server specific details
        static std::shared_ptr<Connection> make_conn(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                const std::vector<ustring>& alpns,
                std::chrono::nanoseconds handshake_timeout,
                std::optional<ustring> remote_pk = std::nullopt,
                ngtcp2_pkt_hd* hdr = nullptr);

        void packet_io_ready();

        TLSSession* get_session() const;

        ustring_view remote_key() const override;

        Direction direction() const override { return dir; }

        size_t active_streams() const override { return streams.size(); }

        void halt_events();
        bool is_closing() const { return closing; }
        void set_closing() { closing = true; }
        bool is_draining() const { return draining; }
        void set_draining() { draining = true; }
        stream_data_callback get_default_data_callback() const;

        const ConnectionID& scid() const override { return _source_cid; }
        const ConnectionID& dcid() const { return _dest_cid; }

        const Path& path() const { return _path; }
        const Address& local() const override { return _path.local; }
        const Address& remote() const override { return _path.remote; }

        Endpoint& endpoint() { return _endpoint; }
        const Endpoint& endpoint() const { return _endpoint; }

        ustring_view selected_alpn() const override;

        uint64_t get_streams_available() const override;
        size_t get_max_datagram_size() const override;
        uint64_t get_max_streams() const override { return _max_streams; }
        bool datagrams_enabled() const override { return _datagrams_enabled; }
        bool packet_splitting_enabled() const override { return _packet_splitting; }

        // public debug functions; to be removed with friend test fixture class
        int last_cleared() const override;

        void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        void close_connection(uint64_t error_code = 0) override;

        // This mutator is called from the gnutls code after cert verification (if it is successful)
        void set_validated() { _is_validated = true; }

        bool is_validated() const override { return _is_validated; }

        // These are public so we can access them from the ngtcp free floating functions
        // (on_handshake_completed and on_handshake_confirmed) and when the connection is closed
        connection_established_callback conn_established_cb;
        connection_closed_callback conn_closed_cb;

      private:
        // private Constructor (publicly construct via `make_conn` instead, so that we can properly
        // set up the shared_from_this shenanigans).
        Connection(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                const std::vector<ustring>& alpns,
                std::chrono::nanoseconds handshake_timeout,
                std::optional<ustring> remote_pk = std::nullopt,
                ngtcp2_pkt_hd* hdr = nullptr);

        Endpoint& _endpoint;
        std::shared_ptr<IOContext> context;
        Direction dir;
        const ConnectionID _source_cid;
        ConnectionID _dest_cid;
        Path _path;
        const uint64_t _max_streams{DEFAULT_MAX_BIDI_STREAMS};
        const bool _datagrams_enabled{false};
        const bool _packet_splitting{false};
        std::atomic<bool> _congested{false};
        bool _is_validated{false};

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

        bool draining = false;
        bool closing = false;

        // Invokes the stream_construct_cb, if present; if not present, or if it returns nullptr,
        // then the given `make_stream` gets invoked to create a default stream.
        std::shared_ptr<Stream> construct_stream(
                const std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)>& default_stream,
                std::optional<int64_t> stream_id = std::nullopt);

        std::shared_ptr<Stream> queue_incoming_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) override;

        std::shared_ptr<Stream> open_stream_impl(
                std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream) override;

        std::shared_ptr<Stream> get_stream_impl(int64_t id) override;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        std::map<int64_t, std::shared_ptr<Stream>> stream_queue;

        int64_t next_incoming_stream_id = is_outbound() ? 1 : 0;

        // datagram "pseudo-stream"
        std::shared_ptr<DatagramIO> datagrams;
        // "pseudo-stream" to represent ngtcp2 stream ID -1
        std::shared_ptr<Stream> pseudo_stream;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        int init(
                ngtcp2_settings& settings,
                ngtcp2_transport_params& params,
                ngtcp2_callbacks& callbacks,
                std::chrono::nanoseconds handshake_timeout);

        io_result read_packet(const Packet& pkt);

        std::shared_ptr<dgram_interface> di;

      public:
        // public to be called by endpoint handing this connection a packet
        void handle_conn_packet(const Packet& pkt);
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_closed(int64_t id, uint64_t app_code);
        void check_pending_streams(uint64_t available);
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

#ifndef NDEBUG
        ~Connection() override;
#endif
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
