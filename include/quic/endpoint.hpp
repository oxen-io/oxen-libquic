#pragma once

#include "utils.hpp"
#include "tunnel.hpp"

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

#include <random>
#include <numeric>
#include <optional>
#include <memory>
#include <string>
#include <unordered_map>


namespace std
{
    //  Custom hash is required s.t. unordered_set storing conn_id:shared_ptr<Connection> 
    //  is able to call its implicit constructor
    template <>
    struct hash<ngtcp2_cid>
    {
        size_t
        operator()(const ngtcp2_cid& cid) const
        {
            static_assert(
                alignof(ngtcp2_cid) >= alignof(size_t)
                && offsetof(ngtcp2_cid, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };
}

namespace oxen::quic
{
    class Connection;

    using conn_id = ngtcp2_cid;
    using conn_ptr = std::shared_ptr<Connection>;

    class Endpoint
    {
        public:
            friend class Connection;

            explicit Endpoint(Tunnel& tun);
            virtual ~Endpoint();

            std::array<std::byte, 1500> buf;
            size_t default_stream_bufsize = static_cast<size_t>(64 * 1024);
            // Max theoretical size of a UDP packet is 2^16-1 minus IP/UDP header overhead
            static constexpr size_t max_bufsize = 64 * 1024;
            // Max size of a UDP packet that we'll send
            static constexpr size_t max_pkt_size_v4 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
            static constexpr size_t max_pkt_size_v6 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

            std::shared_ptr<uvw::Loop>
            get_loop();

            void
            handle_packet(const Packet& pkt);
            
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
            std::unordered_map<conn_id, conn_ptr> conns;
            std::queue<std::pair<conn_id, uint64_t>> draining;

            Address local_addr{reinterpret_cast<const sockaddr_in6&>(in6addr_any)};

            std::optional<conn_id>
            handle_initial_packet(const Packet& pkt);

            void
            handle_conn_packet(Connection& conn, const Packet& pkt);

            //  Sends packet to 'destination' containing 'data'. io_result is implicitly
            //  convertible to bool if successful, or error code if not
            io_result
            send_packet(const Address& destination, bstring data, uint8_t ecn);

            void
            send_version_negotiation(const ngtcp2_version_cid& vid, const Address& source);

            conn_ptr 
            get_conn(const conn_id& cid);

            bool
            delete_conn(const conn_id& cid);

            void
            check_timeouts();

            void
            close_conn(Connection& conn, int code = NGTCP2_NO_ERROR, std::string_view msg = ""sv);

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
            write_packet_header(uint16_t pseudo_port, uint8_t ecn) = 0;
    };

} // namespace oxen::quic
