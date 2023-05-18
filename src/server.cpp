#include "server.hpp"
#include "connection.hpp"
#include "crypto.hpp"

#include <ngtcp2/ngtcp2.h>

#include <memory>
#include <cstddef>


namespace oxen::quic
{
    Server::~Server()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (expiry_timer)
            expiry_timer->close();
    }


    std::shared_ptr<uvw::UDPHandle>
    Server::get_handle(Address& addr)
    {
        // server handles are indexed by local bind addr
        auto handle = context->udp_handles.find(addr);

        return (handle != context->udp_handles.end()) ? handle->second.first : nullptr;
    }


    std::shared_ptr<uvw::UDPHandle>
    Server::get_handle(Path& p)
    {
        // because server handles are indexed by local bind addr, when we call connection::send(), the remote
        // address is passed. as a result, this overload allows us to pass a path (s.t. we can find by local addr)
        for (const auto& h : context->udp_handles)
        {
            if (p.local == h.first)
                return h.second.first;
        }

        return nullptr;
    }


    std::shared_ptr<Connection>
    Server::accept_initial_connection(Packet& pkt, ConnectionID& dcid)
    {
        log::info(log_cat, "Accepting new connection...");

        ngtcp2_pkt_hd hdr;

        auto rv = ngtcp2_accept(&hdr, u8data(pkt.data), pkt.data.size());

        if (rv < 0) // catches all other possible ngtcp2 errors
        {
            log::warning(log_cat, "Error: invalid packet received, length=%{}", pkt.data.size());
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_0RTT)
        {
            log::warning(log_cat, "Error: 0RTT is currently not utilized in this implementation; dropping packet");
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_INITIAL && hdr.tokenlen)
        {
            log::warning(log_cat, "Error: Unexpected token in initial packet");
            return nullptr;
        }

        // when receiving a packet from a client, the remote address (server local address) will
        // be the index of the udp_handle in the server context
        auto result = context->udp_handles.find(pkt.path.local);
        if (result == context->udp_handles.end())
            return nullptr;
        
        auto ctx = result->second.second;
        auto handle = result->second.first;

        for (;;)
        {
            if (auto [itr, res] = conns.emplace(ConnectionID::random(), std::shared_ptr<Connection>{}); res)
            {
                auto conn = std::make_shared<Connection>(this, handler, itr->first, hdr, pkt.path, ctx);
                log::debug(log_cat, "Mapping ngtcp2_conn in server registry to source_cid:{} (dcid: {})", *conn->source_cid.data, *conn->dest_cid.data);
                itr->second = conn;
                return conn;
            }
        }
    }
}   // namespace oxen::quic
