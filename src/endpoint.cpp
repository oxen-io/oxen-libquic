#include "endpoint.hpp"
#include "connection.hpp"
#include "utils.hpp"

#include <ngtcp2/version.h>
#include <uvw/timer.h>
#include <ev.h>
#include <ngtcp2/ngtcp2.h>

#include <optional>
#include <cstddef>


namespace oxen::quic
{
    Endpoint::Endpoint(Tunnel& tun)  : tunnel_ep{tun} 
    {
        expiry_timer = get_loop()->resource<uvw::TimerHandle>();
        expiry_timer->on<uvw::TimerEvent>([this](const auto&, auto&){ check_timeouts(); });
        expiry_timer->start(250ms, 250ms);

        fprintf(stderr, "Successfully created QUIC endpoint\n");
    };

    Endpoint::~Endpoint()
    {
        if (expiry_timer)
            expiry_timer->close();
    }


    std::shared_ptr<uvw::Loop>
    Endpoint::get_loop()
    {
        return (tunnel_ep.ev_loop) ? tunnel_ep.ev_loop : nullptr;
    }


    void
    Endpoint::handle_packet(const Packet& pkt)
    {
        auto dcid_opt = handle_initial_packet(pkt);

        if (!dcid_opt)
        {
            fprintf(stderr, "Error: initial packet handling failed\n");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        fprintf(stderr, "Incoming connection ID: {%s}\n", dcid.data);
        auto cptr = get_conn(dcid);

        if (!cptr)
        {
            cptr = accept_initial_connection(pkt);
            if (!cptr)
            {
                fprintf(stderr, "Error: connection could not be created\n");
                return;
            }
        }

        handle_conn_packet(*cptr, pkt);
        return;
    }


    std::optional<conn_id>
    Endpoint::handle_initial_packet(const Packet& pkt)
    {
        ngtcp2_version_cid vid;
        auto rv = ngtcp2_pkt_decode_version_cid(&vid, u8data(pkt.data), pkt.data.size(), NGTCP2_MAX_CIDLEN);

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {   // version negotiation has not been sent yet, ignore packet
            send_version_negotiation(vid, pkt.path.remote);
            return std::nullopt;
        }
        if (rv != 0)
        {
            fprintf(stderr, "Error: failed to decode QUIC packet header [code: %s]", ngtcp2_strerror(rv));
            return std::nullopt;
        }

        if (vid.dcidlen > NGTCP2_MAX_CIDLEN)
        {
            fprintf(stderr, "Error: destination ID is longer than NGTCP2_MAX_CIDLEN\n");
            return std::nullopt;
        }

        auto c_id = conn_id{.datalen=vid.dcidlen};
        std::memmove(c_id.data, vid.dcid, vid.dcidlen);

        return std::make_optional<conn_id>(c_id);
    }


    void
    Endpoint::handle_conn_packet(Connection& conn, const Packet& pkt)
    {
        if (ngtcp2_conn_is_in_closing_period(conn))
        {
            fprintf(stderr, "Erorr: connection (CID: %s) is in closing period; dropping connection\n", conn.source_cid.data);
            return;
        }

        if (conn.draining)
        {
            fprintf(stderr, "Error: connection is already draining; dropping\n");
        }
    }


    void
    Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, const Address& source)
    {
        std::array<std::byte, max_pkt_size_v4> _buf;
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto rv = ngtcp2_pkt_write_version_negotiation(
            u8data(_buf),
            _buf.size(),
            std::uniform_int_distribution<uint8_t>{0, 255}(rand),
            vid.dcid,
            vid.dcidlen,
            vid.scid,
            vid.scidlen,
            versions.data(),
            versions.size());
        if (rv <= 0)
        {
            fprintf(stderr, "Erorr: Failed to construct version negotiation packet: %s\n", ngtcp2_strerror(rv));
            return;
        }

        tunnel_ep.send_packet(source, bstring{_buf.data(), static_cast<size_t>(rv)}, 0, std::byte{2});
    }


    void
    Endpoint::check_timeouts()
    {
        auto now = get_timestamp();

        while (!draining.empty() && draining.front().second < now)
        {
            if (auto it = conns.find(draining.front().first); it != conns.end())
            {
                fprintf(stderr, "Deleting connection %s\n", it->first.data);
                conns.erase(it);
            }
            draining.pop();
        }
    }


    conn_ptr
    Endpoint::get_conn()
    {
        auto it = conns.begin();
        
        if (it == conns.end())
            return nullptr;

        return it->second;
    }


    conn_ptr
    Endpoint::get_conn(const conn_id& cid)
    {
        if (auto it = conns.find(cid); it != conns.end())
            return it->second;

        return nullptr;
    }

}   // namespace oxen::quic
