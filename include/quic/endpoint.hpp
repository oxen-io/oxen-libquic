#pragma once

#include "utils.hpp"

#include <cstddef>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw/async.h>
#include <uvw/loop.h>
#include <uvw/timer.h>
#include <uvw/poll.h>

#include <queue>
#include <random>
#include <numeric>
#include <optional>
#include <memory>
#include <string>
#include <unordered_map>


namespace std
{
    //  Custom hash is required s.t. unordered_set storing ConnectionID:shared_ptr<Connection> 
    //  is able to call its implicit constructor
    template <>
    struct hash<oxen::quic::ConnectionID>
    {
        size_t
        operator()(const oxen::quic::ConnectionID& cid) const
        {
            static_assert(
                alignof(oxen::quic::ConnectionID) >= alignof(size_t)
                && offsetof(oxen::quic::ConnectionID, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };
}

namespace oxen::quic
{
    class Connection;
    class Tunnel;
    using conn_ptr = std::shared_ptr<Connection>;

    class Endpoint
    {

        public:
            friend class Connection;

            explicit Endpoint(Tunnel& tun);
            virtual ~Endpoint();

            std::array<std::byte, 1500> buf;
            size_t default_stream_bufsize = static_cast<size_t>(64 * 1024);

            std::shared_ptr<uvw::Loop>
            get_loop();

            void
            handle_packet(const Packet& pkt);

            void
    		close_connection(Connection& conn, int code, std::string_view msg = ""sv);

            void
            delete_connection(const ConnectionID &cid);

            conn_ptr 
            get_conn();

        protected:
            Tunnel& tunnel_ep;

            std::shared_ptr<uvw::TimerHandle> expiry_timer;

            // Data structures used to keep track of various types of connections
            //
            //  conns: 
            //      When a client establishes a new connection, it provides its own source CID (scid) and
            //      destination CID (dcid), which it sends to the server. The primary Connection instance is
            //      stored as a shared_ptr indexd by scid
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
            //  draining:
            //      Stores all connections that are labeled as draining (duh). They are kept around for a short
            //      period of time allowing any lagging packets to be caught
            //  
            //      They are indexed by connection ID, storing the removal time as a uint64_t value
            //
            std::unordered_map<ConnectionID, conn_ptr> conns;
            std::queue<std::pair<ConnectionID, uint64_t>> draining;

            Address local_addr{reinterpret_cast<const sockaddr_in&>(in6addr_any)};

            std::optional<ConnectionID>
            handle_initial_packet(const Packet& pkt);

            void
            handle_conn_packet(Connection& conn, const Packet& pkt);

            void
            send_version_negotiation(const ngtcp2_version_cid& vid, const Address& source);

            conn_ptr 
            get_conn(const ConnectionID& cid);

            void
            check_timeouts();

            //  Accepts new connection, returning either a ptr to the Connection
            //  object or nullptr if error. Virtual function returns nothing -- 
            //  overrided by Client and Server classes
            inline virtual std::shared_ptr<Connection>
            accept_initial_connection(const Packet& pkt) { return nullptr; }

            //  TOFIX: this may not be necessary for a generalizable quic library,
            //      as it is a lokinet-specific implementation. However, it may be
            //      useful in the future to be able to add our own headers to quic
            //      packets for whatever purpose
            //       
            //  Writes packet header to the beginning of this.buf; this header is
            //  prepended to quic packets to handle quic server routing, consists of:
            //  - type [1 byte]: 1 for client->server packets; 2 for server->client packets 
            //      (other values reserved)
            //  - port [2 bytes, network order]: client pseudoport (i.e. either a source or 
            //      destination port depending on type)
            //  - ecn value [1 byte]: provided by ngtcp2 (Only the lower 2 bits are actually used).
            //
            //  \param psuedo_port - the remote's pseudo-port (will be 0 if the remote is a 
            //      server, > 0 for a client remote)
            //  \param ecn - the ecn value from ngtcp2
            //
            //  Returns the number of bytes written to buf
            virtual size_t
            write_packet_header(uint16_t pseudo_port, uint8_t ecn) { return 0; };
    };

} // namespace oxen::quic
