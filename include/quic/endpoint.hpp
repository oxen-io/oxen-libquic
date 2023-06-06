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
#include <unordered_map>
#include <uvw.hpp>

#include "connection.hpp"
#include "context.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Connection;
    class Handler;

    class Endpoint
    {
        friend class Connection;

      public:
        explicit Endpoint(std::shared_ptr<Handler>& quic_manager);
        virtual ~Endpoint() { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };

        std::shared_ptr<Handler> handler;

        std::shared_ptr<uvw::Loop> get_loop();

        void handle_packet(Packet& pkt);

        void close_connection(Connection& conn, int code = NGTCP2_NO_ERROR, std::string_view msg = "NO_ERROR"sv);

        void delete_connection(const ConnectionID& cid);

        Connection* get_conn(ConnectionID ID);

        void call_async_all(async_callback_t async_cb);

        void close_conns();

        virtual std::shared_ptr<uvw::UDPHandle> get_handle(Address& addr) = 0;

        virtual std::shared_ptr<uvw::UDPHandle> get_handle(Path& p) = 0;

      protected:
        std::shared_ptr<uvw::TimerHandle> expiry_timer;

        // Data structures used to keep track of various types of connections
        //
        // conns:
        //      When a client establishes a new connection, it provides its own source CID (scid)
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
        //
        std::unordered_map<ConnectionID, std::unique_ptr<Connection>> conns;
        std::queue<std::pair<ConnectionID, uint64_t>> draining;

        std::optional<ConnectionID> handle_initial_packet(Packet& pkt);

        void handle_conn_packet(Connection& conn, Packet& pkt);

        io_result read_packet(Connection& conn, Packet& pkt);

        io_result send_packets(Path& p, send_buffer_t& buf, size_t n_pkts);

        io_result send_packet(Path& p, bstring_view data);

        void send_version_negotiation(const ngtcp2_version_cid& vid, Path& p);

        void check_timeouts();

        // Accepts new connection, returning either a ptr to the Connection
        // object or nullptr if error. Virtual function returns nothing --
        // overrided by Client and Server classes
        virtual Connection* accept_initial_connection(Packet& pkt, ConnectionID& dcid) = 0;

        // NOTE: this may not be necessary for a generalizable quic library,
        //      as it is a lokinet-specific implementation. However, it may be
        //      useful in the future to be able to add our own headers to quic
        //      packets for whatever purpose
        //
        // Writes packet header to the beginning of this.buf; this header is
        // prepended to quic packets to handle quic server routing, consists of:
        // - type [1 byte]: 1 for client->server packets; 2 for server->client packets
        //      (other values reserved)
        // - port [2 bytes, network order]: client pseudoport (i.e. either a source or
        //      destination port depending on type)
        // - ecn value [1 byte]: provided by ngtcp2 (Only the lower 2 bits are actually used).
        //
        // \param psuedo_port - the remote's pseudo-port (will be 0 if the remote is a
        //      server, > 0 for a client remote)
        // \param ecn - the ecn value from ngtcp2
        //
        // Returns the number of bytes written to buf
        virtual size_t write_packet_header(uint16_t pseudo_port, uint8_t ecn) { return 0; };
    };

}  // namespace oxen::quic
