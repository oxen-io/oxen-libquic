#pragma once

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <event2/event.h>

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
#include "network.hpp"
#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint : public std::enable_shared_from_this<Endpoint>
    {
      private:
        void handle_ep_opt(opt::enable_datagrams dc);
        void handle_ep_opt(opt::outbound_alpns alpns);
        void handle_ep_opt(opt::inbound_alpns alpns);
        void handle_ep_opt(opt::handshake_timeout timeout);
        void handle_ep_opt(dgram_data_callback dgram_cb);
        void handle_ep_opt(connection_established_callback conn_established_cb);
        void handle_ep_opt(connection_closed_callback conn_closed_cb);

        // Takes a std::optional-wrapped option that does nothing if the optional is empty,
        // otherwise passes it through to the above.  This is here to allow runtime-dependent
        // options (i.e. where whether or not the option is required is not known at compile time).
        template <typename Opt>
        void handle_ep_opt(std::optional<Opt> option)
        {
            if (option)
                handle_ep_opt(std::move(*option));
        }

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
            _init_internals();
            ((void)handle_ep_opt(std::forward<Opt>(opts)), ...);
        }

        template <typename... Opt>
        void listen(Opt&&... opts)
        {

            static_assert(
                    (0 + ... + std::is_convertible_v<remove_cvref_t<Opt>, std::shared_ptr<TLSCreds>>) == 1,
                    "Endpoint listen requires exactly one std::shared_ptr<TLSCreds> argument");

            std::promise<void> p;
            auto f = p.get_future();

            net.call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    inbound_ctx = std::make_shared<IOContext>(Direction::INBOUND, std::forward<Opt>(opts)...);
                    _set_context_globals(inbound_ctx);
                    _accepting_inbound = true;

                    log::debug(log_cat, "Inbound context ready for incoming connections");

                    p.set_value();
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            f.get();
        }

        // creates new outbound connection to remote; emplaces conn/interface pair in outbound map
        template <typename... Opt>
        std::shared_ptr<connection_interface> connect(RemoteAddress remote, Opt&&... opts)
        {
            std::promise<std::shared_ptr<Connection>> p;
            auto f = p.get_future();

            if (!remote.is_addressable())
                throw std::invalid_argument("Address must be addressible to connect");

            if (_local.is_ipv6() && !remote.is_ipv6())
                remote.map_ipv4_as_ipv6();

            Path _path = Path{_local, remote};

            net.call([&opts..., &p, path = _path, this, remote_pk = std::move(remote).get_remote_key()]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    outbound_ctx = std::make_shared<IOContext>(Direction::OUTBOUND, std::forward<Opt>(opts)...);
                    _set_context_globals(outbound_ctx);

                    for (;;)
                    {
                        if (auto [itr, success] = conns.emplace(ConnectionID::random(), nullptr); success)
                        {
                            itr->second = Connection::make_conn(
                                    *this,
                                    itr->first,
                                    ConnectionID::random(),
                                    std::move(path),
                                    outbound_ctx,
                                    outbound_alpns,
                                    handshake_timeout,
                                    remote_pk);

                            p.set_value(itr->second);
                            return;
                        }
                    }
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

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

        const std::shared_ptr<event_base>& get_loop() { return net.loop(); }

        const std::unique_ptr<UDPSocket>& get_socket() { return socket; }

        // Shortcut for calling net.make_shared<T> to make a std::shared_ptr<T> that has destruction
        // synchronized to the network event loop.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return net.make_shared<T>(std::forward<Args>(args)...);
        }

        // query a list of all active inbound and outbound connections paired with a conn_interface
        std::list<std::shared_ptr<connection_interface>> get_all_conns(std::optional<Direction> d = std::nullopt);

        void handle_packet(const Packet& pkt);

        // Query by connection id; returns nullptr if not found.
        Connection* get_conn(const ConnectionID& ID);

        bool in_event_loop() const;

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
        io_result send_packets(const Address& dest, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts);

        void close_conns(std::optional<Direction> d = std::nullopt);

        void drop_connection(Connection& conn);

        void close_connection(Connection& conn, io_error ec = io_error{0}, std::optional<std::string> msg = std::nullopt);

        void close_connection(ConnectionID cid, io_error code = io_error{0}, std::optional<std::string> msg = std::nullopt);

        const Address& local() const { return _local; }

        bool is_accepting() const { return _accepting_inbound; }

        bool datagrams_enabled() const { return _datagrams; }

        bool packet_splitting_enabled() const { return _packet_splitting; }

        int datagram_bufsize() const { return _rbufsize; }

        Splitting splitting_policy() const { return _policy; }

        // this is public so the connection constructor can delegate initialize its own local copy to call later
        dgram_data_callback dgram_recv_cb;

        // public so connections can call when handling conn packets
        void delete_connection(const ConnectionID& cid);
        void drain_connection(Connection& conn);

        void connection_established(connection_interface& conn);

        int _rbufsize{4096};

      private:
        Network& net;
        Address _local;
        event_ptr expiry_timer;
        std::unique_ptr<UDPSocket> socket;
        bool _accepting_inbound{false};
        bool _datagrams{false};
        bool _packet_splitting{false};
        Splitting _policy{Splitting::NONE};

        std::shared_ptr<IOContext> outbound_ctx;
        std::shared_ptr<IOContext> inbound_ctx;

        std::vector<ustring> outbound_alpns;
        std::vector<ustring> inbound_alpns;
        std::chrono::nanoseconds handshake_timeout{5s};

        void _init_internals();

        void _set_context_globals(std::shared_ptr<IOContext>& ctx);

        void on_receive(const Packet& pkt);

        void _close_connection(Connection& conn, io_error ec, std::string msg);

        // Data structures used to keep track of various types of connections
        //
        // conns:
        //      When an establishes a new connection, it provides its own source CID (scid)
        //      and destination CID (dcid), which it sends to the server. The primary Connection
        //      instance is stored as a shared_ptr indexd by scid
        //          dcid is entirely random string of <=160 bits
        //          scid can be random or store information
        //
        //          When responding, the server will include in its response:
        //          - dcid equal to client's source CID
        //          - New random scid; the client's dcid is not used. This
        //              can also store data like the client's scid
        //
        //          As a result, we end up with:
        //              client.scid == server.dcid
        //              client.dcid == server.scid
        //          with each side randomizing their own scid
        //
        // draining:
        //      Stores all connections that are labeled as draining (duh). They are kept around for
        //      a short period of time allowing any lagging packets to be caught
        //
        //      They are indexed by connection ID, storing the removal time as a time point
        //
        std::unordered_map<ConnectionID, std::shared_ptr<Connection>> conns;

        std::map<std::chrono::steady_clock::time_point, ConnectionID> draining;

        std::optional<ConnectionID> handle_packet_connid(const Packet& pkt);

        // Less efficient wrapper around send_packets that takes care of queuing the packet if the
        // socket is blocked.  This is for rare, one-shot packets only (regular data packets go via
        // more efficient direct send_packets calls with custom resend logic).
        //
        // The callback will be called with the final io_result once the packet is sent (or once it
        // fails).  It can be called immediately, if the packet sends right away, but can be delayed
        // if the socket would block.
        void send_or_queue_packet(
                const Path& p, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback = nullptr);

        void send_version_negotiation(const ngtcp2_version_cid& vid, const Path& p);

        void check_timeouts();

        Connection* accept_initial_connection(const Packet& pkt);
    };

}  // namespace oxen::quic
