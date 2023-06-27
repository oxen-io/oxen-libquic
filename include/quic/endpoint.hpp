#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <cstddef>
#include <memory>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <string>
#include <uvw.hpp>

#include "connection.hpp"
#include "context.hpp"
#include "network.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint : std::enable_shared_from_this<Endpoint>
    {
        friend class Network;
        friend class Connection;
        friend class Stream;

      private:
        const Address local;
        std::shared_ptr<uvw::timer_handle> expiry_timer;
        std::shared_ptr<uv_udp_t> handle;
        bool accepting_inbound{false};
        Network& net;

      public:
        explicit Endpoint(Network& n, const Address& listen_addr);

        template <typename... Opt>
        bool listen(Opt&&... opts)
        {
            std::promise<bool> p;
            auto f = p.get_future();

            net.call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    inbound_ctx = std::make_shared<InboundContext>(std::forward<Opt>(opts)...);
                    accepting_inbound = true;

                    log::debug(log_cat, "Inbound context ready for incoming connections");

                    p.set_value(true);
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

        // creates new outbound connection to remote; emplaces conn/interface pair in outbound map
        template <typename... Opt>
        std::shared_ptr<connection_interface> connect(const Address& remote, Opt&&... opts)
        {
            std::promise<std::shared_ptr<Connection>> p;
            auto f = p.get_future();

            net.call([&opts..., &p, this, remote]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    outbound_ctx = std::make_shared<OutboundContext>(std::forward<Opt>(opts)...);

                    for (;;)
                    {
                        if (auto [itr, success] = conns.emplace(ConnectionID::random(), nullptr); success)
                        {
                            itr->second = std::move(Connection::make_conn(
                                    *this,
                                    itr->first,
                                    ConnectionID::random(),
                                    Path{local, remote},
                                    handle,
                                    outbound_ctx,
                                    Direction::OUTBOUND));

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

        std::shared_ptr<uvw::loop> get_loop();

        // query a list of all active inbound and outbound connections paired with a conn_interface
        std::list<std::shared_ptr<connection_interface>> get_all_conns(std::optional<Direction> d = std::nullopt);

        void handle_packet(Packet& pkt);
        Connection* get_conn_ptr(ConnectionID ID);      // query by conn ID

      protected:
        std::shared_ptr<ContextBase> outbound_ctx = nullptr;
        std::shared_ptr<ContextBase> inbound_ctx = nullptr;

        void close_connection(Connection& conn, int code = NGTCP2_NO_ERROR, std::string_view msg = "NO_ERROR"sv);

        void close_conns(std::optional<Direction> d = std::nullopt);

        void delete_connection(const ConnectionID& cid);

        void drain_connection(Connection& conn);

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
        //      They are indexed by connection ID, storing the removal time as a uint64_t value
        std::unordered_map<ConnectionID, std::shared_ptr<Connection>> conns;

        std::map<std::chrono::steady_clock::time_point, ConnectionID> draining;

        std::optional<ConnectionID> handle_initial_packet(Packet& pkt);

        void handle_conn_packet(Connection& conn, Packet& pkt);

        io_result read_packet(Connection& conn, Packet& pkt);

        io_result send_packets(Path& p, char* buf, size_t* bufsize, size_t& n_pkts);
        io_result send_packet_libuv(Path& p, const char* buf, size_t bufsize, std::function<void()> after_sent = nullptr);
        io_result send_packet(const Path& p, bstring_view data);

        void send_version_negotiation(const ngtcp2_version_cid& vid, Path& p);

        void check_timeouts();

        Connection* accept_initial_connection(Packet& pkt, ConnectionID& dcid);

    };

}  // namespace oxen::quic
