#include "server.hpp"
#include "connection.hpp"

#include <ngtcp2/ngtcp2.h>
#include <cstddef>


namespace oxen::quic
{
    std::shared_ptr<Connection>
    Server::accept_initial_connection(const Packet& pkt)
    {
        ngtcp2_pkt_hd hdr;
        auto rv = ngtcp2_accept(&hdr, u8data(pkt.data), pkt.data.size());

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {
            send_version_negotiation(
                ngtcp2_version_cid{hdr.version, hdr.dcid.data, hdr.dcid.datalen, hdr.scid.data, hdr.scid.datalen}, 
                pkt.path.remote);
            return nullptr;
        }
        if (rv < 0) // catches all other possible ngtcp2 errors
        {
            fprintf(stderr, "Error: invalid packet received, length=%ld\n", pkt.data.size());
            return nullptr;
        }

        if (hdr.type == NGTCP2_PKT_0RTT)
        {
            fprintf(stderr, "Error: 0RTT is currently not utilized in this implementation; dropping packet\n");
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_INITIAL && hdr.tokenlen)
        {
            fprintf(stderr, "Error: Unexpected token in initial packet\n");
            return nullptr;
        }
        
        for (;;)
        {
            if (auto [itr, res] = conns.emplace(ConnectionID::random(), conn_ptr{}); res)
            {
                auto connptr = std::make_shared<Connection>(*this, tunnel_ep, itr->first, hdr, std::move(pkt.path));
                itr->second = connptr;
                return connptr;
            }
        }
    }


    size_t
    Server::write_packet_header(uint16_t pseudo_port, uint8_t ecn)
    {
        buf[0] = SERVER_TO_CLIENT;
        std::memcpy(&buf[1], &pseudo_port, 2);
        buf[3] = std::byte{ecn};
        return 4;
    }
}   // namespace oxen::quic
