#pragma once

#include "address.hpp"
#include "connection.hpp"
#include "connection_ids.hpp"
#include "crypto.hpp"
#include "datagram.hpp"
#include "loop.hpp"
#include "network.hpp"
#include "opt.hpp"
#include "result.hpp"
#include "udp.hpp"
#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

struct event_base;

namespace oxen::quic
{
    struct IOContext;

    class Endpoint : public std::enable_shared_from_this<Endpoint>
    {
      public:
        // Non-movable/non-copyable; you must always hold a Endpoint in a shared_ptr
        Endpoint(const Endpoint&) = delete;
        Endpoint& operator=(const Endpoint&) = delete;
        Endpoint(Endpoint&&) = delete;
        Endpoint& operator=(Endpoint&&) = delete;

        connection_established_callback connection_established_cb;
        connection_closed_callback connection_close_cb;

        template <typename... Opt>
        Endpoint(Network& n, const Address& listen_addr, Opt&&... opts) : net{n}, _local{listen_addr}
        {
            ((void)handle_ep_opt(std::forward<Opt>(opts)), ...);
            _init_internals();
            if (_static_secret.empty())
                _static_secret = make_static_secret();
        }

        template <typename... Opt>
        void listen(Opt&&... opts)
        {
            check_for_tls_creds<Opt...>();

            net.call_get([&opts..., this]() mutable {
                if (inbound_ctx)
                    throw std::logic_error{"Cannot call listen() more than once"};

                // initialize client context and client tls context simultaneously
                inbound_ctx = std::make_shared<IOContext>(Direction::INBOUND, std::forward<Opt>(opts)...);
                // Call the private version for remaining (untemplated) setup:
                _listen();
            });
        }

        template <typename... Opt>
        std::shared_ptr<connection_interface> connect(RemoteAddress remote, Opt&&... opts)
        {
            check_for_tls_creds<Opt...>();

            if (not _manual_routing and !remote.is_addressable())
                throw std::invalid_argument("Address must be addressable to connect");

            if (_local.is_ipv6() && !remote.is_ipv6())
                remote.map_ipv4_as_ipv6();

            std::promise<std::shared_ptr<Connection>> conn_prom;
            net.call([this, &opts..., &conn_prom, remote = std::move(remote)]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    outbound_ctx = std::make_shared<IOContext>(Direction::OUTBOUND, std::forward<Opt>(opts)...);
                    _set_context_globals(outbound_ctx);
                    conn_prom.set_value(_connect(std::move(remote)));
                }
                catch (...)
                {
                    conn_prom.set_exception(std::current_exception());
                }
            });

            return std::static_pointer_cast<connection_interface>(conn_prom.get_future().get());
        }

        // query a list of all active inbound and outbound connections paired with a conn_interface
        std::list<std::shared_ptr<connection_interface>> get_all_conns(std::optional<Direction> d = std::nullopt);

        const Address& local() const { return _local; }

        // Sets the local endpoint address.  This should *only* be used when using manual packet
        // routing; otherwise the address will be set automatically and this method should not
        // normally be called.
        void set_local(Address new_local) { _local = new_local; }

        bool is_accepting() const { return _accepting_inbound; }

        bool datagrams_enabled() const { return _datagrams; }

        bool packet_splitting_enabled() const { return _packet_splitting; }

        int datagram_bufsize() const { return _rbufsize; }

        Splitting splitting_policy() const { return _policy; }

        void close_connection(Connection& conn, io_error ec = io_error{0}, std::optional<std::string> msg = std::nullopt);

        void close_conns(std::optional<Direction> d = std::nullopt);

        std::shared_ptr<Connection> get_conn(ConnectionID rid);

        template <typename... Args>
        void call(Args&&... args)
        {
            net.call(std::forward<Args>(args)...);
        }

        template <typename... Args>
        auto call_get(Args&&... args)
        {
            return net.call_get(std::forward<Args>(args)...);
        }

        template <typename... Args>
        void call_soon(Args&&... args)
        {
            net.call_soon(std::forward<Args>(args)...);
        }

        // Defers destruction of a shared_ptr to a future (but not current) event loop tick.
        void reset_soon(std::shared_ptr<void> ptr) { net.reset_soon(std::move(ptr)); }

        // Shortcut for calling net.make_shared<T> to make a std::shared_ptr<T> that has destruction
        // synchronized to the network event loop.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return net.make_shared<T>(std::forward<Args>(args)...);
        }

        bool in_event_loop() const;

        // Returns a random value suitable for use as the Endpoint static secret value.
        static std::vector<unsigned char> make_static_secret();

        void manually_receive_packet(Packet&& pkt);

        // Wrapper around oxenc::quic::generate_reset_token that prepends the arguments with the
        // endpoint's static secret, as needed by the free function version.
        template <typename... Args>
        auto generate_reset_token(Args&&... args) const
        {
            return quic::generate_reset_token(_static_secret, std::forward<Args>(args)...);
        }

        // Constructs and returns a hashed_reset_token from the given reset token using
        // NGTCP2_STATELESS_RESET_TOKENLEN bytes at `token` and this endpoint's static secret data.
        hashed_reset_token hash_reset_token(std::span<const uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token) const
        {
            return hashed_reset_token{token, _static_secret};
        }
        hashed_reset_token hash_reset_token(const uint8_t* token) const
        {
            return hash_reset_token(
                    std::span<const uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN>{token, NGTCP2_STATELESS_RESET_TOKENLEN});
        }

      private:
        friend class Network;
        friend class Loop;
        friend class Connection;
        friend struct connection_callbacks;
        friend class TestHelper;

        Network& net;
        Address _local;
        event_ptr expiry_timer;
        std::unique_ptr<UDPSocket> socket;
        bool _accepting_inbound{false};
        bool _datagrams{false};
        bool _packet_splitting{false};
        Splitting _policy{Splitting::NONE};
        int _rbufsize{4096};

        opt::manual_routing _manual_routing;

        uint64_t _next_rid{0};

        std::vector<unsigned char> _static_secret;

        std::shared_ptr<IOContext> outbound_ctx;
        std::shared_ptr<IOContext> inbound_ctx;

        std::vector<std::string> outbound_alpns;
        std::vector<std::string> inbound_alpns;
        std::chrono::nanoseconds handshake_timeout{DEFAULT_HANDSHAKE_TIMEOUT};

        std::unordered_map<Address, std::vector<unsigned char>> path_validation_tokens;

        const std::shared_ptr<event_base>& get_loop() { return net._loop->loop(); }

        const std::unique_ptr<UDPSocket>& get_socket() { return socket; }

        // Does the non-templated bit of `listen()`
        void _listen();

        std::shared_ptr<Connection> _connect(RemoteAddress remote);

        void handle_ep_opt(opt::enable_datagrams dc);
        void handle_ep_opt(opt::outbound_alpns alpns);
        void handle_ep_opt(opt::inbound_alpns alpns);
        void handle_ep_opt(opt::alpns alpns);
        void handle_ep_opt(opt::handshake_timeout timeout);
        void handle_ep_opt(dgram_data_callback dgram_cb);
        void handle_ep_opt(connection_established_callback conn_established_cb);
        void handle_ep_opt(connection_closed_callback conn_closed_cb);
        void handle_ep_opt(opt::static_secret ssecret);
        void handle_ep_opt(opt::manual_routing mrouting);

        // Takes a std::optional-wrapped option that does nothing if the optional is empty,
        // otherwise passes it through to the above.  This is here to allow runtime-dependent
        // options (i.e. where whether or not the option is required is not known at compile time).
        template <typename Opt>
        void handle_ep_opt(std::optional<Opt> option)
        {
            if (option)
                handle_ep_opt(std::move(*option));
        }

        void handle_packet(Packet&& pkt);

        /// Attempts to send up to `n_pkts` packets to an address over this endpoint's socket.
        ///
        /// Upon success, updates n_pkts to 0 and returns an io_result with `.success()` true.
        ///
        /// If no packets could be sent because the socket would block, this returns an io_result
        /// with `.blocked()` set to true.  buf/bufsize/n_pkts are not altered (since they have not
        /// been sent).
        ///
        /// If some, but not all, packets were sent then `buf`, `bufsize`, and `n_pkts` will be
        /// updated so that the *unsent* `n_pkts` packets begin at buf, with sizes given in
        /// `bufsize` -- so that the same `buf`/`bufsize`/`n_pkts` can be passed in when ready to
        /// retry sending.
        ///
        /// If a more serious error occurs (other than a blocked socket) then `n_pkts` is set to 0
        /// (effectively dropping all packets) and a result is returned with `.failure()` true (and
        /// `.blocked()` false).
        io_result send_packets(const Path& path, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts);

        // Drops a connection from the endpoint.  This is dangerous to call from *within* methods on
        // a connection itself, and generally should be deferred via a call_soon.
        void _drop_connection(Connection& conn, io_error err);
        // Schedules the connection to be dropped from the endpoint via call_soon; safe to use from
        // within Connection calls.
        void drop_connection(Connection& conn, io_error err);

        dgram_data_callback dgram_recv_cb;

        void delete_connection(Connection& conn);
        void drain_connection(Connection& conn);

        void connection_established(connection_interface& conn);

        void store_path_validation_token(Address remote, std::vector<unsigned char> token);

        std::optional<std::vector<unsigned char>> get_path_validation_token(const Address& remote);

        void initial_association(Connection& conn);

        void associate_reset(const uint8_t* token, Connection& conn);

        void dissociate_reset(const uint8_t* token, Connection& conn);

        void associate_cid(quic_cid qcid, Connection& conn, bool weakly = false);

        void associate_cid(const ngtcp2_cid* cid, Connection& conn);

        void dissociate_cid(const ngtcp2_cid* cid, Connection& conn);

        void dissociate_cid(quic_cid qcid, Connection& conn);

        const std::vector<unsigned char>& static_secret() const { return _static_secret; }

        Connection* fetch_associated_conn(const quic_cid& cid);

        ConnectionID next_reference_id();

        void _init_internals();
        void _init_static_secret();

        bool verify_retry_token(const Packet& pkt, ngtcp2_pkt_hd* hdr, ngtcp2_cid* ocid);

        bool verify_token(const Packet& pkt, ngtcp2_pkt_hd* hdr);

        void send_retry(const Packet& pkt, ngtcp2_pkt_hd* hdr);

        void send_stateless_connection_close(const Packet& pkt, ngtcp2_pkt_hd* hdr, io_error ec = io_error{0});

        void _set_context_globals(std::shared_ptr<IOContext>& ctx);

        void _close_conns(std::optional<Direction> d);

        void _close_connection(Connection& conn, io_error ec, std::string msg);

        void _execute_close_hooks(Connection& conn, io_error ec = io_error{0});

        // Test method
        Connection* get_conn(const quic_cid& ID);

        /// Connection Containers
        ///
        ///     When establishing a new connection, the quic client provides its own source CID (scid)
        /// and destination CID (dcid), which it sends to the server. The QUIC standard allows for an
        /// endpoint to be reached at any of `n` (where n >= 2) connection ID's -- this value is currently
        /// hard-coded to 8 active CID's at once.
        ///
        /// When responding, the server will include in its response:
        ///     - dcid equal to client's source CID
        ///     - New scid generated by the server; the client's dcid is not used beyond the handshake.
        ///
        /// Before that response is ACKed by the client (which completes the handshake on the
        /// server) a client using 0-RTT might still send 0-RTT frames, still using the initial dcid
        /// that the client generated.
        ///
        /// As a result, we end up with:
        ///     client.scid == server.dcid
        ///     client.dcid == server.scid
        /// with each side randomizing their own scid.
        ///
        ///     Internally, the connection is assigned a unique reference ID. All possible CID's at which
        /// the endpoint can be reached are keyed to that reference ID in `conn_lookup`, allowing for rapid
        /// access to the unique reference ID by which the connection pointer can be found.
        /// The primary Connection
        /// instance is stored as a shared_ptr indexd by scid
        ///
        ///     When closing (we closed) or draining (they closed) connections, they must be kept around for a short period
        /// of time to allow for any lagging packets to be caught. The unique reference ID is keyed to removal time formatted
        /// as a time point
        ///
        std::unordered_map<ConnectionID, std::shared_ptr<Connection>> conns;

        std::unordered_map<quic_cid, ConnectionID> conn_lookup;

        std::unordered_map<hashed_reset_token, ConnectionID> reset_token_conns;

        std::map<std::chrono::steady_clock::time_point, ConnectionID> draining_closing;

        std::optional<quic_cid> handle_packet_connid(const Packet& pkt);

        // Less efficient wrapper around send_packets that takes care of queuing the packet if the
        // socket is blocked.  This is for rare, one-shot packets only (regular data packets go via
        // more efficient direct send_packets calls with custom resend logic).
        //
        // The callback will be called with the final io_result once the packet is sent (or once it
        // fails).  It can be called immediately, if the packet sends right away, but can be delayed
        // if the socket would block.
        void send_or_queue_packet(
                const Path& p, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback = nullptr);

        void send_stateless_reset(const Packet& pkt, quic_cid& cid);

        void send_version_negotiation(const ngtcp2_version_cid& vid, Path p);

        void check_timeouts();

        // Attempts to interpret the packet as an initial connection.  If the packet is acceptable,
        // a new Connection is created and a pointer to it is returned.  The bool indicates whether
        // the request has been handled:
        // - always true when a non-nullptr Connection* is returned
        // - otherwise:
        //   - true if the packet has been dealt with, such as illiciting a retry.  The caller
        //     should do nothing else with it.
        //   - false if the packet did not look like a connection, and the caller can try something
        //     else.
        std::pair<Connection*, bool> accept_initial_connection(const Packet& pkt);
        Connection* check_stateless_reset(const Packet& pkt);

        template <typename... Opt>
        static constexpr void check_for_tls_creds()
        {
            static_assert(
                    (0 + ... + std::is_convertible_v<std::remove_cvref_t<Opt>, std::shared_ptr<TLSCreds>>) == 1,
                    "Endpoint listen/connect require exactly one std::shared_ptr<TLSCreds> argument");
        }
    };

}  // namespace oxen::quic
