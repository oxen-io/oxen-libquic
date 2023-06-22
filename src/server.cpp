#include "server.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
}

#include <cstddef>
#include <memory>

#include "connection.hpp"
#include "crypto.hpp"

namespace oxen::quic
{
    Server::~Server()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (expiry_timer)
            expiry_timer->close();
    }

    std::shared_ptr<Stream> Server::open_stream(
            ConnectionID conn_id, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        return open_stream(get_conn(conn_id), std::move(data_cb), std::move(close_cb));
    }

    std::shared_ptr<Stream> Server::open_stream(
            const Address& remote_addr, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        return open_stream(get_conn(remote_addr), std::move(data_cb), std::move(close_cb));
    }

    std::shared_ptr<Stream> Server::open_stream(
            Connection* conn, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        log::trace(log_cat, "Opening server stream...");

        return conn->get_new_stream(
                (context->stream_data_cb) ? context->stream_data_cb : std::move(data_cb), std::move(close_cb));
    }

    std::shared_ptr<uv_udp_t> Server::get_handle(Address& addr)
    {
        // server handles are indexed by local bind addr
        auto handle = context->udp_handles.find(addr);

        return (handle != context->udp_handles.end()) ? handle->second.first : nullptr;
    }

    std::shared_ptr<uv_udp_t> Server::get_handle(Path& p)
    {
        // because server handles are indexed by local bind addr, when we call connection::send(),
        // the remote address is passed. as a result, this overload allows us to pass a path (s.t.
        // we can find by local addr)
        for (const auto& h : context->udp_handles)
        {
            if (p.local == h.first)
                return h.second.first;
        }

        return nullptr;
    }

    Connection* Server::accept_initial_connection(Packet& pkt, ConnectionID& dcid)
    {
        log::info(log_cat, "Accepting new connection...");

        ngtcp2_pkt_hd hdr;

        auto rv = ngtcp2_accept(&hdr, u8data(pkt.data), pkt.data.size());

        if (rv < 0)  // catches all other possible ngtcp2 errors
        {
            log::warning(
                    log_cat,
                    "Warning: unexpected packet received, length={}, code={}, continuing...",
                    pkt.data.size(),
                    ngtcp2_strerror(rv));
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_0RTT)
        {
            log::error(
                    log_cat,
                    "Error: 0RTT is currently not utilized in this implementation; dropping "
                    "packet");
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_INITIAL && hdr.tokenlen)
        {
            log::warning(log_cat, "Warning: Unexpected token in initial packet");
            return nullptr;
        }

        // when receiving a packet from a client, the remote address (server local address) will
        // be the index of the udp_handle in the server context
        auto result = context->udp_handles.find(pkt.path.local);
        if (result == context->udp_handles.end())
            return nullptr;

        auto _ctx = std::dynamic_pointer_cast<GNUTLSContext>(result->second.second);

        // if this is the first connection, take the exact TLS context from UDP_handles; if not,
        // construct a new one in-place using only the cert/key pair to reconfigure gnutls specific details
        log::debug(log_cat, "Currently active conns: {}", context->server->conns.size() + 1);

        auto ctx = (context->server->conns.size() != 0) ? GNUTLSCert{_ctx->gcert}.into_context() : _ctx;

        for (;;)
        {
            if (auto [itr, res] = conns.emplace(ConnectionID::random(), nullptr); res)
            {
                auto conn = std::make_unique<Connection>(*this, handler, itr->first, hdr, pkt.path, ctx, context->config);
                log::debug(
                        log_cat,
                        "Mapping ngtcp2_conn in server registry to source_cid:{} (dcid: {})",
                        *conn->source_cid.data,
                        *conn->dest_cid.data);
                itr->second = std::move(conn);
                return itr->second.get();
            }
        }
    }
}  // namespace oxen::quic
