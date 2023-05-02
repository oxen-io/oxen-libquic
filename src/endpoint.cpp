#include "endpoint.hpp"
#include "connection.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <ngtcp2/version.h>
#include <uvw/timer.h>
#include <ev.h>
#include <ngtcp2/ngtcp2.h>

#include <optional>
#include <cstddef>


namespace oxen::quic
{
    Endpoint::Endpoint(std::shared_ptr<Handler>& quic_manager)
    {
        handler = quic_manager;

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
        return (handler->ev_loop) ? handler->ev_loop : nullptr;
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


    void
    Endpoint::close_connection(Connection& conn, int code, std::string_view msg)
    {
        fprintf(stderr, "Closing connection (CID: %s)\n", conn.source_cid.data);

        if (!conn || conn.closing || conn.draining)
            return;
        
        if (code == NGTCP2_ERR_IDLE_CLOSE)
        {
            fprintf(stderr, 
                "Connection (CID: %s) passed idle expiry timer; closing now without close packet\n", 
                conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            fprintf(stderr, 
            "Connection (CID: %s) passed idle expiry timer; closing now with close packet\n", 
            conn.source_cid.data);
        }

        ngtcp2_connection_close_error err;
        ngtcp2_connection_close_error_set_transport_error_liberr(
            &err, 
            code, 
            reinterpret_cast<uint8_t*>(const_cast<char*>(msg.data())), 
            msg.size());
        
        conn.conn_buffer.resize(max_pkt_size_v4);
        Path path;
        ngtcp2_pkt_info pkt_info;

        auto written = ngtcp2_conn_write_connection_close(
            conn, path, &pkt_info, u8data(conn.conn_buffer), conn.conn_buffer.size(), &err, get_timestamp());

        if (written <= 0)
        {
            fprintf(stderr, "Error: Failed to write connection close packet: ");
            fprintf(stderr, "[%s]\n", (written < 0) ? 
                strerror(written) : 
                "[Error Unknown: closing pkt is 0 bytes?]");
            
            delete_connection(conn.source_cid);
            return;
        }
        // ensure we have enough write space
        assert(written <= (long)conn.conn_buffer.size());

        /*
        if (auto rv = handler.send_data(conn.path.remote, conn.conn_buffer, 0); not rv)
        {
            fprintf(stderr, 
                "Error: failed to send close packet [code: %s]; removing connection (CID: %s)\n", 
                strerror(rv.error_code), conn.source_cid.data);
            delete_connection(conn.source_cid);
        }
        */

    }


    void
    Endpoint::delete_connection(const ConnectionID &cid)
    {
        auto target = conns.find(cid);
        if (target == conns.end())
        {
            fprintf(stderr, "Error: could not delete connection [ID: %s]; could not find \n", cid.data);
            return;
        }

        auto c_ptr = target->second;

        if (c_ptr->on_closing)
        {
            c_ptr->on_closing(*c_ptr);
            c_ptr->on_closing = nullptr;
        }
        
        conns.erase(target);
    }


    std::optional<ConnectionID>
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

        return std::make_optional<ConnectionID>(vid.dcid, vid.dcidlen);
    }


    void
    Endpoint::handle_conn_packet(Connection& conn, const Packet& pkt)
    {
        if (auto rv = ngtcp2_conn_is_in_closing_period(conn); rv != 0)
        {
            fprintf(stderr, "Error: connection (CID: %s) is in closing period; dropping connection\n", conn.source_cid.data);
            close_connection(conn, rv);
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
            0xfe,//std::uniform_int_distribution<uint8_t>(0, 255)(make_mt19937),
            vid.dcid,
            vid.dcidlen,
            vid.scid,
            vid.scidlen,
            versions.data(),
            versions.size());
        if (rv <= 0)
        {
            fprintf(stderr, "Error: Failed to construct version negotiation packet: %s\n", ngtcp2_strerror(rv));
            return;
        }

        //handler.send_data(source, bstring{_buf.data(), static_cast<size_t>(rv)}, 0);
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


    std::shared_ptr<Connection>
    Endpoint::get_conn(ConnectionID ID)
    {
        auto it = conns.find(ID);
        
        if (it == conns.end())
            return nullptr;

        return it->second;
    }
}   // namespace oxen::quic
