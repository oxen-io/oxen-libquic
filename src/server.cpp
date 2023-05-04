#include "server.hpp"
#include "connection.hpp"
#include "crypto.hpp"

#include <ngtcp2/ngtcp2.h>

#include <memory>
#include <cstddef>


namespace oxen::quic
{
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
        for (auto h : context->udp_handles)
        {
            if (p.local == h.first)
                return h.second.first;
        }

        return nullptr;
    }


    std::shared_ptr<Connection>
    Server::accept_initial_connection(Packet& pkt)
    {
        fprintf(stderr, "Accepting new connection...\n");

        ngtcp2_pkt_hd hdr;

        auto rv = ngtcp2_accept(&hdr, u8data(pkt.data), pkt.data.size());

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {
            fprintf(stderr, "Server sending version negotiation...\n");
            send_version_negotiation(
                ngtcp2_version_cid{hdr.version, hdr.dcid.data, hdr.dcid.datalen, hdr.scid.data, hdr.scid.datalen}, 
                pkt.path);
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
            auto conn_id = ConnectionID::random();

            // when receiving a packet from a client, the remote address (server local address) will
            // be the index of the udp_handle in the server context
            auto result = context->udp_handles.find(pkt.path.local);
            if (result == context->udp_handles.end())
                return nullptr;
            
            auto ctx = result->second.second;
            auto handle = result->second.first;

            auto conn_ptr = std::make_shared<Connection>(this, handler, conn_id, hdr, pkt.path, ctx);
            // conn_ptr->tls_context = ctx;

            conn_ptr->on_stream_available = [](Connection& conn) 
            {
                fprintf(stderr, "QUIC connection established, streams now available\n");
                try 
                {
                    conn.open_stream();
                }
                catch (const std::exception& e)
                {
                    fprintf(stderr, "%s\n", e.what());
                }
            };

            conns.emplace(conn_id, conn_ptr);

            return conn_ptr;
        }
    }
}   // namespace oxen::quic
