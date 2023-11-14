#include "endpoint.hpp"

#include "opt.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>
#ifdef __linux__
#include <netinet/udp.h>
#endif
}

#include <cstddef>
#include <list>
#include <optional>

#include "connection.hpp"
#include "internal.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    void Endpoint::handle_ep_opt(opt::enable_datagrams dc)
    {
        _datagrams = true;
        _packet_splitting = dc.split_packets;
        _policy = dc.mode;
        _rbufsize = dc.bufsize;

        log::trace(
                log_cat,
                "User has activated endpoint datagram support with {} split-packet support",
                _packet_splitting ? "" : "no");
    }

    void Endpoint::handle_ep_opt(opt::outbound_alpns alpns)
    {
        outbound_alpns = std::move(alpns.alpns);
    }

    void Endpoint::handle_ep_opt(opt::inbound_alpns alpns)
    {
        inbound_alpns = std::move(alpns.alpns);
    }

    void Endpoint::handle_ep_opt(opt::handshake_timeout timeout)
    {
        handshake_timeout = timeout;
    }

    void Endpoint::handle_ep_opt(dgram_data_callback func)
    {
        log::trace(log_cat, "Endpoint given datagram recv callback");
        dgram_recv_cb = std::move(func);
    }

    void Endpoint::handle_ep_opt(post_receive_callback func)
    {
        log::trace(log_cat, "Endpoint given post-receive callback");
        _post_receive = std::move(func);
    }

    void Endpoint::handle_ep_opt(connection_established_callback conn_established_cb)
    {
        log::trace(log_cat, "Endpoint given connection established callback");
        connection_established_cb = std::move(conn_established_cb);
    }

    void Endpoint::handle_ep_opt(connection_closed_callback conn_closed_cb)
    {
        log::trace(log_cat, "Endpoint given connection closed callback");
        connection_close_cb = std::move(conn_closed_cb);
    }

    void Endpoint::_init_internals()
    {
        log::debug(log_cat, "Starting new UDP socket on {}", _local);
        socket = std::make_unique<UDPSocket>(
                get_loop().get(),
                _local,
                [this](const auto& packet) { handle_packet(packet); },
                [this] {
                    if (_post_receive)
                        _post_receive();
                });

        _local = socket->address();

        expiry_timer.reset(event_new(
                get_loop().get(),
                -1,          // Not attached to an actual socket
                EV_PERSIST,  // Stays active (i.e. repeats) once fired
                [](evutil_socket_t, short, void* self) { static_cast<Endpoint*>(self)->check_timeouts(); },
                this));
        timeval exp_interval;
        exp_interval.tv_sec = 0;
        exp_interval.tv_usec = 250'000;
        event_add(expiry_timer.get(), &exp_interval);
    }

    void Endpoint::_set_context_globals(std::shared_ptr<IOContext>& ctx)
    {
        ctx->config.datagram_support = _datagrams;
        ctx->config.split_packet = _packet_splitting;
        ctx->config.policy = _policy;
    }

    std::list<std::shared_ptr<connection_interface>> Endpoint::get_all_conns(std::optional<Direction> d)
    {
        std::list<std::shared_ptr<connection_interface>> ret{};

        for (const auto& c : conns)
        {
            if (d)
            {
                if (c.second->direction() == d)
                    ret.emplace_back(c.second);
            }
            else
                ret.emplace_back(c.second);
        }

        return ret;
    }

    void Endpoint::close_conns(std::optional<Direction> d)
    {
        for (const auto& c : conns)
        {
            if (d)
            {
                if (c.second->direction() == d)
                    close_connection(*c.second.get());
            }
            else
                close_connection(*c.second.get());
        }
    }

    void Endpoint::drain_connection(Connection& conn)
    {
        if (conn.is_draining())
            return;

        conn.halt_events();
        conn.set_draining();

        const auto* err = ngtcp2_conn_get_ccerr(conn);

        log::debug(
                log_cat,
                "Dropping connection (CID: {}), Reason: {}",
                conn.scid(),
                err->reason ? std::string_view{reinterpret_cast<const char*>(err->reason), err->reasonlen} : "None"sv);

        // call close callback
        if (connection_close_cb)
        {
            log::trace(log_cat, "{} Calling Connection closed callback", conn.is_inbound() ? "server" : "client");
            connection_close_cb(conn, err->error_code);
        }

        draining.emplace(get_time() + ngtcp2_conn_get_pto(conn) * 3 * 1ns, conn.scid());

        log::debug(log_cat, "Connection CID: {} marked as draining", conn.scid());
    }

    void Endpoint::handle_packet(const Packet& pkt)
    {
        auto dcid_opt = handle_packet_connid(pkt);

        if (!dcid_opt)
        {
            log::warning(log_cat, "Error: initial packet handling failed");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        log::trace(log_cat, "Incoming connection ID: {}", dcid);
        auto cptr = get_conn(dcid);

        if (!cptr)
        {
            if (_accepting_inbound)
            {
                cptr = accept_initial_connection(pkt);

                if (!cptr)
                {
                    log::warning(log_cat, "Error: connection could not be created");
                    return;
                }
            }
            else
            {
                log::info(log_cat, "Dropping packet; unknown connection ID to endpoint not accepting inbound conns");
                return;
            }
        }

        cptr->handle_conn_packet(pkt);

        return;
    }

    void Endpoint::close_connection(ConnectionID cid, io_error ec, std::string_view msg)
    {
        for (auto& [scid, conn] : conns)
        {
            if (scid == cid)
                return close_connection(*conn, std::move(ec), std::move(msg));
        }

        log::warning(log_cat, "Could not find connection (CID: {}) for closure", cid);
    }

    void Endpoint::drop_connection(Connection& conn)
    {
        const auto* err = ngtcp2_conn_get_ccerr(conn);

        log::debug(
                log_cat,
                "Dropping connection (CID: {}), Reason: {}",
                conn.scid(),
                err->reason ? std::string_view{reinterpret_cast<const char*>(err->reason), err->reasonlen} : "None"sv);

        if (connection_close_cb)
        {
            log::trace(log_cat, "{} Calling Connection closed callback", conn.is_inbound() ? "server" : "client");
            connection_close_cb(conn, err->error_code);
        }

        delete_connection(conn.scid());
    }

    void Endpoint::close_connection(Connection& conn, io_error ec, std::string_view msg)
    {
        log::debug(log_cat, "Closing connection (CID: {})", *conn.scid().data);

        if (conn.is_closing() || conn.is_draining())
            return;

        if (ec.ngtcp2_code() == NGTCP2_ERR_IDLE_CLOSE)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now without close "
                    "packet",
                    *conn.scid().data);
            drop_connection(conn);
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (ec.ngtcp2_code() == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now with close packet",
                    *conn.scid().data);
        }

        // mark connection as closing
        conn.halt_events();
        conn.set_closing();

        if (connection_close_cb)
        {
            log::trace(log_cat, "{} Calling Connection closed callback", conn.is_inbound() ? "server" : "client");
            connection_close_cb(conn, ec.code());
        }

        ngtcp2_ccerr err;
        ngtcp2_ccerr_default(&err);
        if (ec.is_ngtcp2)
            ngtcp2_ccerr_set_liberr(&err, ec.ngtcp2_code(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        else
            ngtcp2_ccerr_set_application_error(&err, ec.code(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);
        ngtcp2_pkt_info pkt_info{};

        auto written = ngtcp2_conn_write_connection_close(
                conn, nullptr, &pkt_info, u8data(buf), buf.size(), &err, get_timestamp().count());

        if (written <= 0)
        {
            log::warning(
                    log_cat,
                    "Error: Failed to write connection close packet: {}",
                    (written < 0) ? strerror(written) : "[Error Unknown: closing pkt is 0 bytes?]"s);

            delete_connection(conn.scid());
            return;
        }
        // ensure we had enough write space
        assert(static_cast<size_t>(written) <= buf.size());
        buf.resize(written);

        send_or_queue_packet(conn.path(), std::move(buf), /*ecn=*/0, [this, cid = conn.scid()](io_result rv) {
            if (rv.failure())
            {
                log::warning(
                        log_cat,
                        "Error: failed to send close packet [{}]; removing connection [CID: {}]",
                        rv.str_error(),
                        cid);
                delete_connection(cid);
            }
        });
    }

    void Endpoint::delete_connection(const ConnectionID& cid)
    {
        if (auto itr = conns.find(cid); itr != conns.end())
        {
            conns.erase(itr);
            log::debug(log_cat, "Successfully deleted connection [ID: {}]", *cid.data);
        }
        else
            log::warning(log_cat, "Error: could not delete connection [ID: {}]; could not find", *cid.data);
    }

    void Endpoint::connection_established(connection_interface& conn)
    {
        log::trace(log_cat, "Connection established, calling user callback [ID: {}]", conn.scid());
        if (connection_established_cb)
            connection_established_cb(conn);
    }

    std::optional<ConnectionID> Endpoint::handle_packet_connid(const Packet& pkt)
    {
        ngtcp2_version_cid vid;
        auto rv = ngtcp2_pkt_decode_version_cid(&vid, u8data(pkt.data), pkt.data.size(), NGTCP2_MAX_CIDLEN);

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {  // version negotiation has not been sent yet, ignore packet
            send_version_negotiation(vid, pkt.path);
            return std::nullopt;
        }
        if (rv != 0)
        {
            log::debug(log_cat, "Error: failed to decode QUIC packet header [code: {}]", ngtcp2_strerror(rv));
            return std::nullopt;
        }

        if (vid.dcidlen > NGTCP2_MAX_CIDLEN)
        {
            log::debug(
                    log_cat,
                    "Error: destination ID is longer than NGTCP2_MAX_CIDLEN ({} > {})",
                    vid.dcidlen,
                    NGTCP2_MAX_CIDLEN);
            return std::nullopt;
        }

        return std::make_optional<ConnectionID>(vid.dcid, vid.dcidlen);
    }

    Connection* Endpoint::accept_initial_connection(const Packet& pkt)
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
            log::error(log_cat, "Error: 0RTT is not utilized in this implementation; dropping packet");
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_INITIAL && hdr.tokenlen)
        {
            log::warning(log_cat, "Warning: Unexpected token in initial packet");
            return nullptr;
        }

        log::debug(log_cat, "Constructing path using packet path: {}", pkt.path);

        assert(net.in_event_loop());
        for (;;)
        {
            if (auto [itr, success] = conns.emplace(ConnectionID::random(), nullptr); success)
            {
                itr->second = Connection::make_conn(
                        *this, itr->first, hdr.scid, pkt.path, inbound_ctx, inbound_alpns, handshake_timeout, &hdr);
                return itr->second.get();
            }
        }
    }

    io_result Endpoint::send_packets(const Address& dest, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(log_cat, "Cannot send packets on closed socket (to reach {})", dest);
            return io_result{EBADF};
        }
        assert(n_pkts >= 1 && n_pkts <= MAX_BATCH);

        log::trace(log_cat, "Sending {} UDP packet(s) to {}...", n_pkts, dest);

        auto [ret, sent] = socket->send(dest, buf, bufsize, ecn, n_pkts);

        if (ret.failure() && !ret.blocked())
        {
            log::error(log_cat, "Error sending packets to {}: {}", dest, ret.str_error());
            n_pkts = 0;  // Drop any packets, as we had a serious error
            return ret;
        }

        if (sent < n_pkts)
        {
            if (sent == 0)  // Didn't send *any* packets, i.e. we got entirely blocked
                log::debug(log_cat, "UDP sent none of {}", n_pkts);

            else
            {
                // We sent some but not all, so shift the unsent packets back to the beginning of buf/bufsize
                log::debug(log_cat, "UDP undersent {}/{}", sent, n_pkts);
                size_t offset = std::accumulate(bufsize, bufsize + sent, size_t{0});
                size_t len = std::accumulate(bufsize + sent, bufsize + n_pkts, size_t{0});
                std::memmove(buf, buf + offset, len);
                std::copy(bufsize + sent, bufsize + n_pkts, bufsize);
                n_pkts -= sent;
            }

            // We always return EAGAIN (so that .blocked() is true) if we failed to send all, even
            // if that isn't strictly what we got back as the return value (sendmmsg gives back a
            // non-error on *partial* success).
            return io_result{EAGAIN};
        }
        else
            n_pkts = 0;

        return ret;
    }

    void Endpoint::send_or_queue_packet(
            const Path& p, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(log_cat, "Cannot sent to dead socket for path {}", p);
            if (callback)
                callback(io_result{EBADF});
            return;
        }

        size_t n_pkts = 1;
        size_t bufsize = buf.size();
        auto res = send_packets(p.remote, buf.data(), &bufsize, ecn, n_pkts);

        if (res.blocked())
        {
            socket->when_writeable([this, p, buf = std::move(buf), ecn, cb = std::move(callback)]() mutable {
                send_or_queue_packet(p, std::move(buf), ecn, std::move(cb));
            });
        }
    }

    void Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, const Path& p)
    {
        uint8_t rint;
        gnutls_rnd(GNUTLS_RND_RANDOM, &rint, 8);
        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto nwrite = ngtcp2_pkt_write_version_negotiation(
                u8data(buf),
                buf.size(),
                rint,
                vid.dcid,
                vid.dcidlen,
                vid.scid,
                vid.scidlen,
                versions.data(),
                versions.size());
        if (nwrite <= 0)
        {
            log::warning(log_cat, "Error: Failed to construct version negotiation packet: {}", ngtcp2_strerror(nwrite));
            return;
        }

        send_or_queue_packet(p, std::move(buf), /*ecn=*/0);
    }

    void Endpoint::check_timeouts()
    {
        auto now = get_time();

        const auto& f = draining.begin();

        while (!draining.empty() && f->first < now)
        {
            if (auto itr = conns.find(f->second); itr != conns.end())
            {
                log::debug(log_cat, "Deleting connection {}", *itr->first.data);
                conns.erase(itr);
            }
            draining.erase(f);
        }
    }

    Connection* Endpoint::get_conn(const ConnectionID& id)
    {
        if (auto it = conns.find(id); it != conns.end())
            return it->second.get();
        return nullptr;
    }

    bool Endpoint::in_event_loop() const
    {
        return net.in_event_loop();
    }

}  // namespace oxen::quic
