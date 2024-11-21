#pragma once

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
}

#include <cstddef>
#include <list>
#include <memory>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <string>
#include <unordered_map>

#include "connection.hpp"
#include "context.hpp"
#include "gnutls_crypto.hpp"
#include "network.hpp"
#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
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
            check_verification_scheme<Opt...>(this);

            net.call_get([&opts..., this]() mutable {
                if (inbound_ctx)
                    throw std::logic_error{"Cannot call listen() more than once"};

                // initialize client context and client tls context simultaneously
                inbound_ctx = std::make_shared<IOContext>(Direction::INBOUND, std::forward<Opt>(opts)...);
                // Call the private version for remaining (untemplated) setup:
                _listen();
            });
        }

        template <concepts::quic_address_type T, typename... Opt>
        std::shared_ptr<connection_interface> connect(T remote, Opt&&... opts)
        {
            check_for_tls_creds<Opt...>();
            check_address_scheme<T, Opt...>();

            std::promise<std::shared_ptr<Connection>> p;
            auto f = p.get_future();

            if (not _manual_routing and !remote.is_addressable())
                throw std::invalid_argument("Address must be addressible to connect");

            if (_local.is_ipv6() && !remote.is_ipv6())
                remote.map_ipv4_as_ipv6();

            net.call([this, &opts..., &p, remote = std::move(remote)]() mutable {
                quic_cid qcid{};
                auto next_rid = next_reference_id();

                try
                {
                    // initialize client context and client tls context simultaneously
                    outbound_ctx = std::make_shared<IOContext>(Direction::OUTBOUND, std::forward<Opt>(opts)...);
                    _set_context_globals(outbound_ctx);
                    _connect(std::move(remote), qcid, next_rid, p);
                }
                catch (...)
                {
                    conn_lookup.erase(qcid);
                    conns.erase(next_rid);
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

        // query a list of all active inbound and outbound connections paired with a conn_interface
        std::list<std::shared_ptr<connection_interface>> get_all_conns(std::optional<Direction> d = std::nullopt);

        const Address& local() const { return _local; }

        bool is_accepting() const { return _accepting_inbound; }

        bool datagrams_enabled() const { return _datagrams; }

        bool packet_splitting_enabled() const { return _packet_splitting; }

        int datagram_bufsize() const { return _rbufsize; }

        Splitting splitting_policy() const { return _policy; }

        void close_connection(Connection& conn, io_error ec = io_error{0}, std::optional<std::string> msg = std::nullopt);

        void close_conns(std::optional<Direction> d = std::nullopt);

        std::shared_ptr<connection_interface> get_conn(ConnectionID rid);

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
        static ustring make_static_secret();

        void manually_receive_packet(Packet&& pkt);

        bool zero_rtt_enabled() const { return _0rtt_enabled; }
        unsigned int zero_rtt_window() const { return _0rtt_window; }

        bool stateless_reset_enabled() const { return _stateless_reset_enabled; }

        int validate_anti_replay(gtls_session_ticket ticket, time_t exp);
        void store_session_ticket(gtls_session_ticket ticket);
        gtls_ticket_ptr get_session_ticket(const ustring_view& remote_pk);

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
        bool _0rtt_enabled{false};
        unsigned int _0rtt_window{};

        bool _stateless_reset_enabled{true};

        gtls_db_validate_cb _validate_0rtt_ticket;
        gtls_db_get_cb _get_session_ticket;
        gtls_db_put_cb _put_session_ticket;

        uint64_t _next_rid{0};

        ustring _static_secret;

        std::shared_ptr<IOContext> outbound_ctx;
        std::shared_ptr<IOContext> inbound_ctx;

        std::vector<ustring> outbound_alpns;
        std::vector<ustring> inbound_alpns;
        std::chrono::nanoseconds handshake_timeout{DEFAULT_HANDSHAKE_TIMEOUT};

        std::unordered_map<ustring_view, gtls_ticket_ptr> session_tickets;

        std::unordered_map<Address, ustring> encoded_transport_params;

        std::unordered_map<Address, ustring> path_validation_tokens;

        const std::shared_ptr<event_base>& get_loop() { return net._loop->loop(); }

        const std::unique_ptr<UDPSocket>& get_socket() { return socket; }

        // Does the non-templated bit of `listen()`
        void _listen();

        void _connect(RemoteAddress remote, quic_cid qcid, ConnectionID rid, std::promise<std::shared_ptr<Connection>>& p);

        void _connect(Address remote, quic_cid qcid, ConnectionID rid, std::promise<std::shared_ptr<Connection>>& p);

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
        void handle_ep_opt(opt::enable_0rtt_ticketing rtt);
        void handle_ep_opt(opt::disable_stateless_reset rst);

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

        void drop_connection(Connection& conn, io_error err);

        dgram_data_callback dgram_recv_cb;

        void delete_connection(Connection& conn);
        void drain_connection(Connection& conn);

        void connection_established(connection_interface& conn);

        void store_0rtt_transport_params(Address remote, ustring encoded_params);

        std::optional<ustring> get_0rtt_transport_params(const Address& remote);

        void store_path_validation_token(Address remote, ustring token);

        std::optional<ustring> get_path_validation_token(const Address& remote);

        void initial_association(Connection& conn);

        void activate_cid(const ngtcp2_cid* cid, const uint8_t* token, Connection& conn);

        void deactivate_cid(const ngtcp2_cid* cid, Connection& conn);

        void associate_cid(quic_cid qcid, Connection& conn);

        void associate_cid(const ngtcp2_cid* cid, Connection& conn);

        void dissociate_cid(const ngtcp2_cid* cid, Connection& conn);

        void dissociate_cid(quic_cid qcid, Connection& conn);

        const ustring& static_secret() const { return _static_secret; }

        Connection* fetch_associated_conn(quic_cid& cid);

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

        // Test methods
        void set_local(Address new_local) { _local = new_local; }
        Connection* get_conn(const quic_cid& ID);

        /// Connection Containers
        ///
        ///     When establishing a new connection, the quic client provides its own source CID (scid)
        /// and destination CID (dcid), which it sends to the server. The QUIC standard allows for an
        /// endpoint to be reached at any of `n` (where n >= 2) connection ID's -- this value is currently
        /// hard-coded to 8 active CID's at once. Specifically, the dcid is entirely random string of <=160 bits
        /// while the scid can be random or store information.
        ///
        /// When responding, the server will include in its response:
        ///     - dcid equal to client's source CID
        ///     - New random scid; the client's dcid is not used. This can also store data like the client's scid
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
        std::map<ConnectionID, std::shared_ptr<Connection>> conns;

        std::unordered_map<quic_cid, ConnectionID> conn_lookup;

        // only used if stateless reset enabled
        std::unordered_map<quic_cid, std::shared_ptr<gtls_reset_token>> reset_token_lookup;
        std::unordered_map<std::shared_ptr<gtls_reset_token>, quic_cid> reset_token_map;

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

        Connection* check_stateless_reset(const Packet& pkt, quic_cid& cid);

        void send_version_negotiation(const ngtcp2_version_cid& vid, Path p);

        void check_timeouts();

        Connection* accept_initial_connection(const Packet& pkt, quic_cid& cid);

        template <typename... Opt>
        static constexpr void check_for_tls_creds()
        {
            static_assert(
                    (0 + ... + std::is_convertible_v<std::remove_cvref_t<Opt>, std::shared_ptr<TLSCreds>>) == 1,
                    "Endpoint listen/connect require exactly one std::shared_ptr<TLSCreds> argument");
        }

        template <typename... Opt>
        static void check_verification_scheme(Endpoint* e)
        {
            if constexpr ((std::is_same_v<opt::disable_key_verification, std::remove_cvref_t<Opt>> || ...))
            {
                if (e->zero_rtt_enabled())
                    throw std::invalid_argument{"Disabling key verification is incompatible with 0rtt ticketing!"};
            }
        }

        template <concepts::quic_address_type T, typename... Opt>
        static constexpr void check_address_scheme()
        {
            if constexpr ((std::is_same_v<opt::disable_key_verification, std::remove_cvref_t<Opt>> || ...))
            {
                static_assert(std::is_same_v<T, Address>, "Disabling key verification requires keyless address!");
            }
        }
    };

}  // namespace oxen::quic
