#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>

#include "connection_ids.hpp"
#include "context.hpp"
#include "format.hpp"
#include "types.hpp"

namespace oxen::quic
{
    struct dgram_interface;
    class Network;

    inline constexpr uint64_t MAX_ACTIVE_CIDS{8};
    inline constexpr size_t NGTCP2_RETRY_SCIDLEN{18};

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
        template <concepts::stream_derived_type StreamT, typename... Args, typename EndpointDeferred = Endpoint>
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
        template <concepts::stream_derived_type StreamT, typename... Args, typename EndpointDeferred = Endpoint>
            requires std::derived_from<StreamT, Stream>
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
        template <concepts::stream_derived_type StreamT = Stream>
        std::shared_ptr<StreamT> maybe_stream(int64_t id)
        {
            auto s = get_stream_impl(id);
            if (!s)
                return nullptr;
            if constexpr (!std::same_as<StreamT, Stream>)
            {
                if (auto st = std::dynamic_pointer_cast<StreamT>(std::move(s)))
                    return st;
                throw std::invalid_argument{
                        "Stream ID " + std::to_string(id) + " is not an instance of the requested Stream subclass"};
            }
            else
                return s;
        }

        /// Returns a stream object for the stream with the given id, if the stream exists (and, if
        /// StreamT is specified, is of the given Stream subclass).  Otherwise throws
        /// std::out_of_range if the stream was not found, and std::invalid_argument if the stream
        /// was found, but is not an instance of StreamT.
        template <concepts::stream_derived_type StreamT = Stream>
        std::shared_ptr<StreamT> get_stream(int64_t id)
        {
            if (auto s = maybe_stream<StreamT>(id))
                return s;
            throw std::out_of_range{"Could not find a stream with ID " + std::to_string(id)};
        }

        template <oxenc::basic_char CharType>
            requires(!std::same_as<CharType, std::byte>)
        void send_datagram(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive = nullptr)
        {
            send_datagram(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        template <oxenc::basic_char Char>
        void send_datagram(std::vector<Char>&& buf)
        {
            auto keep_alive = std::make_shared<std::vector<Char>>(std::move(buf));
            std::basic_string_view<Char> view{keep_alive->data(), keep_alive->size()};
            send_datagram(view, std::move(keep_alive));
        }

        template <oxenc::basic_char CharType>
        void send_datagram(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            send_datagram(view, std::move(keep_alive));
        }

        virtual void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) = 0;

        virtual Endpoint& endpoint() = 0;
        virtual const Endpoint& endpoint() const = 0;

        virtual void set_close_quietly() = 0;

        virtual bool datagrams_enabled() const = 0;
        virtual bool packet_splitting_enabled() const = 0;
        virtual const ConnectionID& reference_id() const = 0;
        virtual bool is_validated() const = 0;
        virtual Direction direction() const = 0;
        virtual ustring_view remote_key() const = 0;
        virtual bool is_inbound() const = 0;
        virtual bool is_outbound() const = 0;
        virtual std::string direction_str() = 0;

        // Non-virtual base class wrappers for the virtual methods of the same name with _impl
        // appended (e.g.  path_impl); these versions in the base class wrap the _impl call in a
        // call_get to return the value synchronously.  Generally external application code should
        // use this, and internal quic code (already in the event loop thread) should use the _impl
        // ones directly.

        /// Returns the number of streams that are currently open
        size_t num_streams_active();

        /// Returns the number of streams that have been created but are not yet active on the
        /// connection; they will become active once the connection negotiates an increase to the
        /// maximum number of streams, *or* when an existing stream closes, opening a stream slot on
        /// the connection.
        size_t num_streams_pending();

        /// Returns the maximum number of active streams that the connection currently allows.
        uint64_t get_max_streams();

        /// Returns the number of new streams that may still be activated on this connection.
        uint64_t get_streams_available();

        /// Returns a copy of the current Path in use by this connection.
        Path path();

        /// Returns a copy of the local address of the path in use by this connection.  (If you want
        /// both local and remote then prefer to call `path()` once instead of local() and remote()
        /// separately).
        Address local();

        /// Returns a copy of the remote address of the path in use by this connection.  (If you
        /// want both local and remote then prefer to call `path()` once instead of local() and
        /// remote() separately).
        Address remote();

        /// Returns the maximum datagram size accepted by this connection.  This depends on the
        /// negotiated QUIC connection and can change over time, but will generally be somewhere in
        /// the 1150-1450 range when not using datagram splitting on the connection, or double that
        /// with datagram splitting enabled.
        size_t get_max_datagram_size();

        /// Obtains the current max datagram size *if* it has changed since the last time this
        /// method was called (or if this method has never been called), otherwise returns nullopt.
        /// This is designed to allow classes to react to changes in the maximum datagram size, if
        /// needed, by periodically polling this and updating as needed when the value changes.
        /// When there have not been changes then calling this is cheap (just an atomic bool
        /// access); a trip to the event loop thread is necessary to retrieve the value when
        /// changed, but changes are relatively infrequent.
        ///
        /// This feature is for non-standard/exotic uses: if you don't care about changes to the
        /// size (for example, if you use splitting and know the size will always be sufficient)
        /// then you can safely never worry about this function.
        virtual std::optional<size_t> max_datagram_size_changed() = 0;

        // WIP functions: these are meant to expose specific aspects of the internal state of connection
        // and the datagram IO object for debugging and application (user) utilization.
        //
        //  last_cleared: returns the index of the last cleared bucket in the recv_buffer
        virtual int last_cleared() const = 0;

        virtual void close_connection(uint64_t error_code = 0) = 0;

        virtual ~connection_interface();

      protected:
        // Unsynchronized access methods suitable only for internal use in contexts where we know we
        // are already inside the event loop thread.  The public APIs for these (without _impl)
        // wraps these in a call_get to make them thread-safe.
        virtual size_t num_streams_active_impl() const = 0;
        virtual size_t num_streams_pending_impl() const = 0;
        virtual uint64_t get_max_streams_impl() const = 0;
        virtual uint64_t get_streams_available_impl() const = 0;
        virtual const Path& path_impl() const = 0;
        virtual const Address& local_impl() const { return path_impl().local; }
        virtual const Address& remote_impl() const { return path_impl().remote; }
        // Returns 0 if datagrams are not available
        virtual size_t get_max_datagram_size_impl() = 0;
    };

    class Connection : public connection_interface
    {
        friend class TestHelper;
        friend struct rotating_buffer;
        friend struct connection_callbacks;

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
        //      default_handshake_timeout: the default timeout for handshaking for the endpoint
        //          (individual connections might have this overridden via connect option).
        //      remote_pk: optional parameter used by clients to verify the pubkey of the remote
        //          endpoint during handshake negotiation. For servers, omit this parameter or
        //          pass std::nullopt
        //		hdr: optional parameter to pass to ngtcp2 for server specific details
        static std::shared_ptr<Connection> make_conn(
                Endpoint& ep,
                ConnectionID rid,
                const quic_cid& scid,
                const quic_cid& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                const std::vector<ustring>& alpns,
                std::chrono::nanoseconds default_handshake_timeout,
                std::optional<ustring> remote_pk = std::nullopt,
                ngtcp2_pkt_hd* hdr = nullptr,
                std::optional<ngtcp2_token_type> token_type = std::nullopt,
                ngtcp2_cid* ocid = nullptr);

        void packet_io_ready();

        TLSSession* get_session() const;

        ustring_view remote_key() const override;

        Direction direction() const override { return dir; }

        size_t num_streams_active_impl() const override { return _streams.size(); }
        size_t num_streams_pending_impl() const override { return pending_streams.size(); }

        void halt_events();
        bool is_closing() const { return closing; }
        void set_closing() { closing = true; }
        bool is_draining() const { return draining; }
        void set_draining() { draining = true; }
        stream_data_callback get_default_data_callback() const;

        bool is_outbound() const override { return _is_outbound; }
        bool is_inbound() const override { return not is_outbound(); }
        std::string direction_str() override { return is_inbound() ? "SERVER"s : "CLIENT"s; }

        const Path& path_impl() const override { return _path; }
        const Address& local_impl() const override { return _path.local; }
        const Address& remote_impl() const override { return _path.remote; }

        Endpoint& endpoint() override { return _endpoint; }
        const Endpoint& endpoint() const override { return _endpoint; }

        ustring_view selected_alpn() const override;

        uint64_t get_streams_available_impl() const override;
        size_t get_max_datagram_size_impl() override;
        uint64_t get_max_streams_impl() const override { return _max_streams; }

        bool datagrams_enabled() const override { return _datagrams_enabled; }
        bool packet_splitting_enabled() const override { return _packet_splitting; }

        bool zero_rtt_enabled() const { return _0rtt_enabled; }
        unsigned int zero_rtt_window() const { return _0rtt_window; }

        bool stateless_reset_enabled() const { return _stateless_reset_enabled; }

        std::optional<size_t> max_datagram_size_changed() override;

        // public debug functions; to be removed with friend test fixture class
        int last_cleared() const override;

        void send_datagram(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        void close_connection(uint64_t error_code = 0) override;

        // This mutator is called from the gnutls code after cert verification (if it is successful)
        void set_validated();

        bool is_validated() const override { return _is_validated; }

        // These are public so we can access them from the ngtcp free floating functions
        // (on_handshake_completed and on_handshake_confirmed) and when the connection is closed
        connection_established_callback conn_established_cb;
        connection_closed_callback conn_closed_cb;

        void set_remote_addr(const ngtcp2_addr& new_remote);

        void store_associated_cid(const quic_cid& cid);

        void delete_associated_cid(const quic_cid& cid);

        std::unordered_set<quic_cid>& associated_cids() { return _associated_cids; }

        int client_handshake_completed();

        int server_handshake_completed();

        int recv_stateless_reset(std::shared_ptr<gtls_reset_token> tok);

        int client_path_validation(const ngtcp2_path* path, bool res, uint32_t flags);

        int server_path_validation(const ngtcp2_path* path, bool res, uint32_t flags);

        void set_new_path(Path new_path);

        const ConnectionID& reference_id() const override { return _ref_id; }

        void set_close_quietly() override;

        bool closing_quietly() const { return _close_quietly; }

        // Called when the endpoint drops its shared pointer to this Connection, to have this
        // Connection clear itself from all of its streams and then drop the streams.  (This is a
        // sort of pseudo-destruction to leave the involved objects as empty shells since there
        // might be shared pointers in application space that keep the connection and/or stream
        // alive after it gets dropped from libquic internal structures).
        void drop_streams();

      private:
        // private Constructor (publicly construct via `make_conn` instead, so that we can properly
        // set up the shared_from_this shenanigans).
        Connection(
                Endpoint& ep,
                ConnectionID rid,
                const quic_cid& scid,
                const quic_cid& dcid,
                const Path& path,
                std::shared_ptr<IOContext> ctx,
                const std::vector<ustring>& alpns,
                std::chrono::nanoseconds default_handshake_timeout,
                std::optional<ustring> remote_pk = std::nullopt,
                ngtcp2_pkt_hd* hdr = nullptr,
                std::optional<ngtcp2_token_type> token_type = std::nullopt,
                ngtcp2_cid* ocid = nullptr);

        Endpoint& _endpoint;
        std::shared_ptr<IOContext> context;
        Direction dir;
        bool _is_outbound;

        const ConnectionID _ref_id;

        std::unordered_set<quic_cid> _associated_cids;

        const quic_cid _source_cid;
        quic_cid _dest_cid;

        Path _path;

        bool _0rtt_enabled{false};
        const unsigned int _0rtt_window{};

        bool _stateless_reset_enabled{false};

        const uint64_t _max_streams{DEFAULT_MAX_BIDI_STREAMS};
        const bool _datagrams_enabled{false};
        const bool _packet_splitting{false};
        size_t _last_max_dgram_size{0};
        std::atomic<bool> _max_dgram_size_changed{true};

        std::atomic<bool> _close_quietly{false};
        std::atomic<bool> _is_validated{false};

        ustring remote_pubkey{};

        std::set<int64_t> _early_streams;

        void make_early_streams(ngtcp2_conn* connptr);

        void revert_early_streams();

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
        std::map<int64_t, std::shared_ptr<Stream>> _streams;
        std::map<int64_t, std::shared_ptr<Stream>> _stream_queue;

        int64_t next_incoming_stream_id = is_outbound() ? 1 : 0;

        // datagram "pseudo-stream"
        std::shared_ptr<DatagramIO> datagrams;
        // "pseudo-stream" to represent ngtcp2 stream ID -1
        std::shared_ptr<Stream> pseudo_stream;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        void init(
                ngtcp2_settings& settings,
                ngtcp2_transport_params& params,
                ngtcp2_callbacks& callbacks,
                std::chrono::nanoseconds handshake_timeout);

        io_result read_packet(const Packet& pkt);

        std::shared_ptr<dgram_interface> di;

        /********* TEST SUITE FUNCTIONALITY *********/
        void set_local_addr(Address new_local);
        bool debug_datagram_drop_enabled{false};
        bool debug_datagram_flip_flop_enabled{false};
        int debug_datagram_counter{0};  // Used for either of the above (only one at a time)

      public:
        // public to be called by endpoint handing this connection a packet
        void handle_conn_packet(const Packet& pkt);
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_execute_close(Stream& s, uint64_t app_code);
        void stream_closed(int64_t id, uint64_t app_code);
        void close_all_streams();
        void check_pending_streams(uint64_t available, bool is_early_stream = false);
        int recv_datagram(bstring_view data, bool fin);
        int ack_datagram(uint64_t dgram_id);
        int recv_token(const uint8_t* token, size_t tokenlen);

        // Implicit conversion of Connection to the underlying ngtcp2_conn* (so that you can pass a
        // Connection directly to ngtcp2 functions taking a ngtcp2_conn* argument).
        template <typename T>
            requires std::same_as<T, ngtcp2_conn>
        operator const T*() const
        {
            return conn.get();
        }
        template <typename T>
            requires std::same_as<T, ngtcp2_conn>
        operator T*()
        {
            return conn.get();
        }

        // returns number of currently pending streams for use in test cases
        size_t num_pending() const { return pending_streams.size(); }

        // Called (from Endpoint) to trigger any required stream timeouts.  Should not be called
        // externally.
        void check_stream_timeouts();

        ~Connection() override;
    };

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref);

        void log_printer(void* user_data, const char* fmt, ...);
    }

}  // namespace oxen::quic
