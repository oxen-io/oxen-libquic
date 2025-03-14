#include "connection.hpp"

#include "context.hpp"
#include "datagram.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
#include "iochannel.hpp"
#include "result.hpp"
#include "stream.hpp"
#include "udp.hpp"
#include "utils.hpp"

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <event2/event.h>

#include <gnutls/crypto.h>

#include <cassert>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iterator>
#include <limits>
#include <list>
#include <memory>
#include <random>
#include <ranges>
#include <stdexcept>
#include <unordered_map>

#ifndef _WIN32
extern "C"
{
#include <sys/time.h>
}
#endif

namespace oxen::quic
{
    using namespace std::literals;

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return *static_cast<Connection*>(conn_ref->user_data);
        }

        void log_printer(void* /*user_data*/, const char* fmt, ...)
        {
            std::array<char, 2048> buf{};
            va_list ap;
            va_start(ap, fmt);
            if (vsnprintf(buf.data(), buf.size(), fmt, ap) >= 0)
                log::debug(log_cat, "{}", buf.data());
            va_end(ap);
        }
    }

    // ngtcp2 internal callback functions (that are deliberately source only, not a published
    // header); we group them all in this struct to make them slightly easier to manage, but more
    // importantly, because `connection_callbacks` is a friend-with-benefits of Endpoint that can
    // touch its privates.
    struct connection_callbacks
    {

        static int on_ack_datagram(ngtcp2_conn* /* conn */, uint64_t dgram_id, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(user_data)->ack_datagram(dgram_id);
        }

        static int on_recv_datagram(
                ngtcp2_conn* /* conn */, uint32_t flags, const uint8_t* data, size_t datalen, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(user_data)->recv_datagram(
                    {reinterpret_cast<const std::byte*>(data), datalen}, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
        }

        static int on_recv_token(ngtcp2_conn* /* conn */, const uint8_t* token, size_t tokenlen, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(user_data)->recv_token(token, tokenlen);
        }

        static int on_recv_stream_data(
                ngtcp2_conn* /*conn*/,
                uint32_t flags,
                int64_t stream_id,
                uint64_t /*offset*/,
                const uint8_t* data,
                size_t datalen,
                void* user_data,
                void* /*stream_user_data*/)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(user_data)->stream_receive(
                    stream_id, {reinterpret_cast<const std::byte*>(data), datalen}, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
        }

        static int on_acked_stream_data_offset(
                ngtcp2_conn* /*conn_*/,
                int64_t stream_id,
                uint64_t offset,
                uint64_t datalen,
                void* user_data,
                void* /*stream_user_data*/)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            log::trace(log_cat, "Ack [{},{}]", offset, offset + datalen);
            return static_cast<Connection*>(user_data)->stream_ack(stream_id, datalen);
        }

        static int on_stream_open(ngtcp2_conn* /*conn*/, int64_t stream_id, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(user_data)->stream_opened(stream_id);
        }

        static int on_stream_close(
                ngtcp2_conn* /*conn*/,
                uint32_t /*flags*/,
                int64_t stream_id,
                uint64_t app_error_code,
                void* user_data,
                void* /*stream_user_data*/)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
            return 0;
        }

        static int on_stream_reset(
                ngtcp2_conn* /*conn*/,
                int64_t stream_id,
                uint64_t /*final_size*/,
                uint64_t app_error_code,
                void* user_data,
                void* /*stream_user_data*/)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
            return 0;
        }

        static int on_recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid, void* user_data)
        {
            int rv = ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
            if (rv == 0)
            {
                // We store the client initial DCID as that will be used by 0-RTT packets that
                // arrive before the handshake completes.  However, since we didn't get the safely
                // choose this, we only set if it not already used (so that a possible collision
                // between the temporary dcid and some scid we generated properly yields to the
                // latter).
                if (auto init_dcid = ngtcp2_conn_get_client_initial_dcid(conn); init_dcid && init_dcid->datalen)
                {
                    auto& conn = *static_cast<Connection*>(user_data);
                    conn.endpoint().associate_cid(*init_dcid, conn, true);
                }
                else
                    log::trace(log_cat, "No initial dcid to associate");
            }
            return rv;
        }

        static int on_handshake_completed(ngtcp2_conn*, void* user_data)
        {
            auto* conn = static_cast<Connection*>(user_data);
            auto dir_str = conn->is_inbound() ? "SERVER"s : "CLIENT"s;

            log::trace(log_cat, "HANDSHAKE COMPLETED on {} connection", dir_str);

            int rv = 0;

            if (conn->is_inbound())
            {
                rv = conn->server_handshake_completed();

                if (conn->conn_established_cb)
                    conn->conn_established_cb(*conn);
                else
                    conn->endpoint().connection_established(*conn);
            }
            else
                rv = conn->client_handshake_completed();

            return rv;
        }

        static int on_handshake_confirmed(ngtcp2_conn*, void* user_data)
        {
            auto* conn = static_cast<Connection*>(user_data);

            // server should never call this, as it "confirms" on handshake completed
            assert(conn->is_outbound());
            log::trace(log_cat, "HANDSHAKE CONFIRMED on CLIENT connection");

            if (conn->conn_established_cb)
                conn->conn_established_cb(*conn);
            else
                conn->endpoint().connection_established(*conn);

            return 0;
        }

        static void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx)
        {
            (void)rand_ctx;
            (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
        }

        static int on_connection_id_status(
                ngtcp2_conn* /* _conn */,
                ngtcp2_connection_id_status_type type,
                uint64_t seq,
                const ngtcp2_cid* cid,
                const uint8_t* token,
                void* user_data)
        {
            if (!token)
                return 0;

            auto* conn = static_cast<Connection*>(user_data);

            auto& ep = conn->endpoint();

            // if token is not null, map to cid
            if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE)
            {
                log::debug(
                        log_cat,
                        "Activating stateless reset token {} for CID[{}]:{} from remote: {}",
                        oxenc::to_hex(token, token + NGTCP2_STATELESS_RESET_TOKENLEN),
                        seq,
                        quic_cid{*cid},
                        conn->remote());
                ep.associate_reset(token, *conn);
            }
            else if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE)
            {
                log::debug(
                        log_cat,
                        "Deactivating stateless reset token {} for CID[{}]:{} from remote: {}",
                        oxenc::to_hex(token, token + NGTCP2_STATELESS_RESET_TOKENLEN),
                        seq,
                        quic_cid{*cid},
                        conn->remote());
                ep.dissociate_reset(token, *conn);
            }

            return 0;
        }

        static int get_new_connection_id(
                ngtcp2_conn* /* _conn */, ngtcp2_cid* cid, uint8_t* tokenptr, size_t cidlen, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;

            cid->datalen = cidlen;
            auto* conn = static_cast<Connection*>(user_data);
            auto& ep = conn->endpoint();

            std::span<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token{tokenptr, NGTCP2_STATELESS_RESET_TOKENLEN};
            try
            {
                ep.generate_reset_token(cid, token);
            }
            catch (const std::exception& e)
            {
                log::warning(log_cat, "{}", e.what());
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }

            log::trace(
                    log_cat,
                    "{} generated new CID for {} with reset token {}",
                    conn->is_outbound() ? "CLIENT" : "SERVER",
                    conn->reference_id(),
                    oxenc::to_hex(token.begin(), token.end()));
            ep.associate_cid(cid, *conn);

            return 0;
        }

        static int remove_connection_id(ngtcp2_conn* /* _conn */, const ngtcp2_cid* cid, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto* conn = static_cast<Connection*>(user_data);
            log::trace(
                    log_cat, "{} dissociating CID for {}", conn->is_outbound() ? "CLIENT" : "SERVER", conn->reference_id());
            conn->endpoint().dissociate_cid(cid, *conn);

            return 0;
        }

        static int extend_max_local_streams_bidi([[maybe_unused]] ngtcp2_conn* _conn, uint64_t max_streams, void* user_data)
        {
            auto& conn = *static_cast<Connection*>(user_data);
            log::debug(
                    log_cat,
                    "max local bidi streams extended on {} {} to {}",
                    conn.direction_str(),
                    conn.reference_id(),
                    max_streams);

            if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn); remaining > 0)
                conn.check_pending_streams(remaining);

            return 0;
        }

        static int on_path_validation(
                ngtcp2_conn* _conn [[maybe_unused]],
                uint32_t flags,
                const ngtcp2_path* path,
                const ngtcp2_path* /* old_path */,
                ngtcp2_path_validation_result res,
                void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto& conn = *static_cast<Connection*>(user_data);
            assert(_conn == conn);

            auto b = res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS;

            if (conn.is_outbound())
                return conn.client_path_validation(path, b, flags);
            else
                return conn.server_path_validation(path, b, flags);
        }

        static int on_early_data_rejected(ngtcp2_conn* _conn [[maybe_unused]], void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto& conn = *static_cast<Connection*>(user_data);
            assert(_conn == conn);

            if (conn._early_data)
            {
                conn._early_data = false;
                log::debug(log_cat, "Server rejected attempt to use 0-RTT; resetting early streams/datagrams");
                conn.revert_early_streams();
                if (conn.datagrams)
                    conn.datagrams->early_data_end(false);
            }
            else
                log::trace(log_cat, "Early data rejected (but this connection was not using early data)");

            return 0;
        }

        static int on_recv_retry(ngtcp2_conn* _conn, const ngtcp2_pkt_hd* hd, void* user_data)
        {
            int rv = ngtcp2_crypto_recv_retry_cb(_conn, hd, user_data);
            if (rv == 0)
            {
                log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

                auto& conn = *static_cast<Connection*>(user_data);
                assert(_conn == conn);

                // ngtcp2 automatically resends lost stream data on a retry, but we also want to
                // allow our known-lost initial datagrams to be resent:
                if (conn._early_data && conn.datagrams)
                {
                    log::debug(log_cat, "Client received a Retry during early data; resetting datagrams");
                    conn.datagrams->early_data_retry();
                }
            }

            return rv;
        }

        static int recv_stateless_reset(
                ngtcp2_conn* _conn [[maybe_unused]], const ngtcp2_pkt_stateless_reset* sr, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto& conn = *static_cast<Connection*>(user_data);
            assert(_conn == conn);

            return conn.recv_stateless_reset(sr->stateless_reset_token);
        }

    };  // struct connection_callbacks

    int Connection::recv_stateless_reset(std::span<const uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token)
    {
        log::trace(log_cat, "Client recv_stateless_reset cb called...");

        hashed_reset_token htok{token, _endpoint.static_secret()};

        if (auto it = _endpoint.reset_token_conns.find(htok); it != _endpoint.reset_token_conns.end())
        {
            log::warning(
                    log_cat,
                    "Received stateless reset for connection ({}) on path: {}; closing immediately!",
                    _ref_id,
                    _path);

            // dropping the connection will drop the reset token we just matched
            _endpoint.drop_connection(*this, io_error{CONN_STATELESS_RESET});
        }
        else
            log::debug(log_cat, "Could not match received stateless reset to any connection!");
        return 0;
    }

    int Connection::client_path_validation(const ngtcp2_path* path, bool success, uint32_t flags)
    {
        log::trace(log_cat, "Client path_validation cb called...");
        assert(is_outbound());

        if (flags & NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR)
        {
            set_remote_addr(path->remote);
            log::debug(log_cat, "Client set new remote ({}) on successful path validation...", _path.remote);
        }
        else if (success)
            log::debug(log_cat, "Client path validation succeeded as no address was provided by server...");
        else
            log::warning(log_cat, "Client path validation failed; no address was provided by server...");

        return 0;
    }

    int Connection::server_path_validation(const ngtcp2_path* path, bool success, uint32_t flags)
    {
        log::trace(log_cat, "Server path_validation cb called...");
        assert(is_inbound());

        if (not success)
        {
            log::warning(log_cat, "Server path validation failed!");
            return 0;
        }

        if (not(flags & NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN))
        {
            log::debug(log_cat, "Server path validation cb did not request a new token...");
            return 0;
        }

        std::array<uint8_t, NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN> token;

        auto len = ngtcp2_crypto_generate_regular_token(
                token.data(),
                _endpoint._static_secret.data(),
                _endpoint._static_secret.size(),
                path->remote.addr,
                path->remote.addrlen,
                get_timestamp().count());

        if (len < 0)
        {
            log::warning(log_cat, "Server unable to generate regular token: {}", ngtcp2_strerror(len));
            return 0;
        }

        if (auto rv = ngtcp2_conn_submit_new_token(*this, token.data(), len); rv != 0)
        {
            log::error(log_cat, "ngtcp2_conn_submit_new_token failed: {}", ngtcp2_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        log::debug(log_cat, "Server completed path validation!");
        return 0;
    }
    void Connection::set_close_quietly()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        _close_quietly = true;
    }

    void Connection::set_new_path(Path new_path)
    {
        _endpoint.call([this, new_path]() { _path = new_path; });
    }

    int Connection::recv_token(const uint8_t* token, size_t tokenlen)
    {
        // This should only be called by the client, and therefore this will always have a value
        _endpoint.store_path_validation_token(_path.remote, {token, token + tokenlen});
        return 0;
    }

    int Connection::client_handshake_completed()
    {
        if (tls_creds->outbound_0rtt())
        {
            const bool accepted = tls_session->get_early_data_accepted();
            log::debug(log_cat, "Early data was {} by server", accepted ? "ACCEPTED" : "REJECTED");

            if (accepted)
            {
                if (datagrams)
                    datagrams->early_data_end(true);
            }
            else
            {
                if (auto rv = ngtcp2_conn_tls_early_data_rejected(*this); rv != 0)
                {
                    log::error(log_cat, "ngtcp2_conn_tls_early_data_rejected failed: {}", ngtcp2_strerror(rv));
                    _early_data = false;
                    return -1;
                }
            }
            _early_data = false;
        }

        return 0;
    }

    int Connection::server_handshake_completed()
    {
        if (tls_creds->inbound_0rtt())
        {
            log::debug(log_cat, "Server handshake completed and we support 0-RTT, sending TLS tickets");
            tls_session->send_session_tickets();
        }

        auto path = ngtcp2_conn_get_path(*this);
        auto now = get_timestamp().count();

        if (auto init_dcid = ngtcp2_conn_get_client_initial_dcid(*this); init_dcid && init_dcid->datalen)
        {
            // We add the initial client dcid when we accept the connection as it is potentially
            // used for 0-RTT, but now that the handshake is completed we can remove it as it isn't
            // allowed to be used anymore.  (But check that we actually added it, because in the
            // case of a collision we don't actually store it).
            quic_cid qcid{*init_dcid};
            if (_associated_cids.count(qcid))
                _endpoint.dissociate_cid(qcid, *this);
        }

        std::array<uint8_t, NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN> token;

        auto len = ngtcp2_crypto_generate_regular_token(
                token.data(),
                _endpoint._static_secret.data(),
                _endpoint._static_secret.size(),
                path->remote.addr,
                path->remote.addrlen,
                now);

        if (len < 0)
        {
            log::warning(log_cat, "Server unable to generate regular token!");
            return 0;
        }

        if (auto rv = ngtcp2_conn_submit_new_token(*this, token.data(), len); rv != 0)
        {
            log::error(log_cat, "ngtcp2_conn_submit_new_token failed: {}", ngtcp2_strerror(rv));
            return -1;
        }

        log::debug(log_cat, "Server successfully submitted regular token on handshake completion...");

        return 0;
    }

    void Connection::set_validated()
    {
        _is_validated = true;

        if (is_inbound())
        {
            auto key = get_session()->remote_key();
            remote_pubkey.assign(key.begin(), key.end());
        }
    }

    int Connection::last_cleared() const
    {
        return datagrams ? datagrams->recv_buffer.last_cleared : -1;
    }

    void Connection::set_remote_addr(const ngtcp2_addr& new_remote)
    {
        _endpoint.call([this, new_remote]() { _path.set_new_remote(new_remote); });
    }

    void Connection::set_local_addr(Address new_local)
    {
        _endpoint.call([this, new_local]() {
            Path new_path{new_local, _path.remote};
            _path = new_path;
        });
    }

    void Connection::store_associated_cid(const quic_cid& cid)
    {
        log::debug(log_cat, "Connection (RID:{}) storing associated cid:{}", _ref_id, cid);
        _associated_cids.insert(cid);
    }

    void Connection::delete_associated_cid(const quic_cid& cid)
    {
        log::debug(log_cat, "Connection (RID:{}) deleting associated cid:{}", _ref_id, cid);
        _associated_cids.erase(cid);
    }

    void Connection::store_associated_reset(const hashed_reset_token& htoken)
    {
        _associated_resets.insert(htoken);
    }

    void Connection::delete_associated_reset(const hashed_reset_token& htoken)
    {
        _associated_resets.erase(htoken);
    }

    uspan Connection::remote_key() const
    {
        return remote_pubkey;
    }

    void Connection::halt_events()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(endpoint().in_event_loop());
        packet_io_trigger.reset();
        packet_retransmit_timer.reset();
        log::debug(log_cat, "Connection ({}) io trigger/retransmit timer events halted", reference_id());
    }

    void Connection::packet_io_ready()
    {
        assert(endpoint().in_event_loop());
        if (packet_io_trigger)
            event_active(packet_io_trigger.get(), 0, 0);
        // else we've reset the trigger (via halt_events), which means the connection is closing/draining/etc.
    }

    void Connection::close_connection(uint64_t error_code)
    {
        _endpoint.close_connection(*this, io_error{error_code});
    }

    void Connection::revert_early_streams()
    {
        assert(endpoint().in_event_loop());
        log::debug(log_cat, "Client reverting early stream data");

        // We need to re-open any opened streams because the remote rejected early data, and when
        // that happens ngtcp2 reverts all stream state.  So we prepend all our streams back into
        // pending_streams (in reverse order so that they will get opened in the same order) then
        // call check_pending_streams to reopen them.
        for (auto& [id, stream] : std::ranges::views::reverse(_streams))
        {
            log::debug(log_cat, "Resetting early stream {} and returning to pending streams", id);
            stream->revert_stream();
            stream->set_ready(false);
            if (!(id & 0x01))
            {  // Client-initiated stream (and we are always the client)
                pending_streams.push_front(std::move(stream));
            }
            else
            {
                // This shouldn't happen because if we're still in early data the server shouldn't
                // have been able to send anything to us yet.
                log::warning(log_cat, "Unexpected non-client-initiated stream {} in early stream reset", id);
                _stream_queue[id] = std::move(stream);
            }
        }
        _streams.clear();
        if (auto remaining = ngtcp2_conn_get_streams_bidi_left(*this); remaining > 0)
            check_pending_streams(remaining);
    }

    void Connection::handle_conn_packet(const Packet& pkt)
    {
        if (auto rv = ngtcp2_conn_in_closing_period(*this); rv != 0)
        {
            log::trace(
                    log_cat,
                    "Note: {} connection {} in closing period; dropping packet",
                    is_inbound() ? "server" : "client",
                    reference_id());
            return;
        }

        if (is_draining())
        {
            log::debug(log_cat, "Note: connection is already draining; dropping");
            return;
        }

        if (read_packet(pkt).success())
            log::trace(log_cat, "done with incoming packet");
        else
            log::trace(log_cat, "read packet failed");  // error will be already logged
    }

    io_result Connection::read_packet(const Packet& pkt)
    {
        auto ts = get_timestamp().count();
        log::trace(log_cat, "Calling ngtcp2_conn_read_pkt...");
        auto data = pkt.data<uint8_t>();
        auto rv = ngtcp2_conn_read_pkt(*this, pkt.path, &pkt.pkt_info, data.data(), data.size(), ts);

        switch (rv)
        {
            case 0:
                packet_io_ready();
                break;
            case NGTCP2_ERR_DRAINING:
                log::trace(log_cat, "Note: {} is draining; signaling endpoint to drain connection", reference_id());
                _endpoint.call_soon([this]() {
                    log::debug(log_cat, "Endpoint draining connection {}", reference_id());
                    _endpoint.drain_connection(*this);
                });
                break;
            case NGTCP2_ERR_PROTO:
                log::trace(
                        log_cat,
                        "Note: {} encountered error {}; signaling endpoint to close connection",
                        reference_id(),
                        ngtcp2_strerror(rv));
                log::debug(log_cat, "Endpoint closing {}", reference_id());
                _endpoint.close_connection(*this, io_error{rv}, "ERR_PROTO"s);
                break;
            case NGTCP2_ERR_DROP_CONN:
                // drop connection without calling ngtcp2_conn_write_connection_close()
                log::trace(
                        log_cat,
                        "Note: {} encountered ngtcp2 error {}; signaling endpoint to delete connection",
                        reference_id(),
                        ngtcp2_strerror(rv));
                _endpoint.drop_connection(*this, io_error{rv});
                break;
            case NGTCP2_ERR_CRYPTO:
                // drop conn without calling ngtcp2_conn_write_connection_close()
                log::trace(
                        log_cat,
                        "Note: {} {} encountered ngtcp2 crypto error {} (code: {}); signaling endpoint to delete "
                        "connection",
                        direction_str(),
                        reference_id(),
                        ngtcp2_conn_get_tls_alert(*this),
                        ngtcp2_strerror(rv));
                _endpoint.drop_connection(*this, io_error{rv});
                break;
            default:
                log::trace(
                        log_cat,
                        "Note: {} encountered error {}; signaling endpoint to close connection",
                        reference_id(),
                        ngtcp2_strerror(rv));
                log::debug(log_cat, "Endpoint closing {}", reference_id());
                _endpoint.close_connection(*this, io_error{rv});
                break;
        }

        return io_result::ngtcp2(rv);
    }

    // note: this does not need to return anything, it is never called except in on_stream_available
    // First, we check the list of pending streams on deck to see if they're ready for broadcast. If
    // so, we move them to the streams map, where they will get picked up by flush_packets and dump
    // their buffers. If none are ready, we keep chugging along and make another stream as usual. Though
    // if none of the pending streams are ready, the new stream really shouldn't be ready, but here we are
    void Connection::check_pending_streams(uint64_t available)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint64_t popped = 0;

        while (!pending_streams.empty() && popped < available)
        {
            auto& str = pending_streams.front();

            if (int rv = ngtcp2_conn_open_bidi_stream(*this, &str->_stream_id, str.get()); rv == 0)
            {
                auto _id = str->_stream_id;
                log::debug(log_cat, "Stream [ID:{}] ready for broadcast, moving out of pending streams", _id);
                str->set_ready();
                popped += 1;
                _streams[_id] = std::move(str);
                pending_streams.pop_front();
            }
            else
                return;
        }
    }

    std::shared_ptr<Stream> Connection::construct_stream(
            const std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)>& default_stream,
            std::optional<int64_t> stream_id)
    {
        std::shared_ptr<Stream> stream;
        if (context->stream_construct_cb)
            stream = context->stream_construct_cb(*this, _endpoint, stream_id);
        if (!stream && default_stream)
            stream = default_stream(*this, _endpoint);
        if (!stream)
            stream = _endpoint.make_shared<Stream>(*this, _endpoint, context->stream_data_cb, context->stream_close_cb);

        return stream;
    }

    std::shared_ptr<Stream> Connection::queue_incoming_stream_impl(
            std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream)
    {
        return _endpoint.call_get([this, &make_stream]() {
            std::shared_ptr<Stream> stream;
            if (make_stream)
                stream = make_stream(*this, _endpoint);
            else
                stream = construct_stream(nullptr);

            assert(!stream->_ready);
            stream->_stream_id = next_incoming_stream_id;
            next_incoming_stream_id += 4;

            log::trace(log_cat, "{} queuing new incoming stream for id {}", direction_str(), stream->_stream_id);

            // If the connection is closing/draining then immediately close it (rather than adding
            // it to the queue), so that what we give back is a closed stream but that has had its
            // steam close callback fired to do any cleanup it needs.  Although this feels slightly
            // weird, it's less clunky than forcing application code to try/catch or worry about a
            // nullptr return from this function.
            if (is_closing() || is_draining())
            {
                log::debug(
                        log_cat,
                        "closing newly queued stream {} immediately; this connection is closed",
                        stream->_stream_id);
                stream_execute_close(*stream, STREAM_ERROR_CONNECTION_CLOSED);
                return stream;
            }

            auto& str = _stream_queue[stream->_stream_id];
            str = std::move(stream);
            return str;
        });
    }

    std::shared_ptr<Stream> connection_interface::queue_incoming_stream()
    {
        return queue_incoming_stream_impl(nullptr);
    }

    std::shared_ptr<Stream> Connection::open_stream_impl(
            std::function<std::shared_ptr<Stream>(Connection& c, Endpoint& e)> make_stream)
    {
        return _endpoint.call_get([this, &make_stream]() {
            std::shared_ptr<Stream> stream;
            if (make_stream)
                stream = make_stream(*this, _endpoint);
            else
                stream = construct_stream(make_stream);

            assert(!stream->_ready);

            if (is_closing() || is_draining())
            {
                log::debug(
                        log_cat,
                        "closing newly opened stream {} immediately; this connection is closed",
                        stream->_stream_id);
                stream_execute_close(*stream, STREAM_ERROR_CONNECTION_CLOSED);
                return stream;
            }

            if (int rv = ngtcp2_conn_open_bidi_stream(*this, &stream->_stream_id, stream.get()); rv != 0)
            {
                log::debug(log_cat, "Stream not ready [Code: {}]; adding to pending streams list", ngtcp2_strerror(rv));
                assert(!stream->_ready);
                pending_streams.push_back(std::move(stream));
                return pending_streams.back();
            }
            else
            {
                log::debug(log_cat, "Stream {} successfully created; ready to broadcast", stream->_stream_id);
                stream->set_ready();
                auto& strm = _streams[stream->_stream_id];
                strm = std::move(stream);
                return strm;
            }
        });
    }

    std::shared_ptr<Stream> connection_interface::open_stream()
    {
        return open_stream_impl(nullptr);
    }

    std::shared_ptr<Stream> Connection::get_stream_impl(int64_t id)
    {
        return _endpoint.call_get([this, id]() -> std::shared_ptr<Stream> {
            if (auto it = _streams.find(id); it != _streams.end())
                return it->second;

            if (auto it = _stream_queue.find(id); it != _stream_queue.end())
                return it->second;

            return nullptr;
        });
    }

    stream_data_callback Connection::get_default_data_callback() const
    {
        return context->stream_data_cb;
    }

    void Connection::on_packet_io_ready()
    {
        auto ts = get_time();
        flush_packets(ts);

        // If we get a failure (e.g. io error) during flush_packets we might have initiated a
        // shutdown which would have deleted and reset the timer (in which case we don't want to try
        // rescheduling it):
        if (!packet_retransmit_timer)
            return;

        schedule_packet_retransmit(ts);
    }

    // RAII class for calling ngtcp2_conn_update_pkt_tx_timer.  If you don't call cancel() on
    // this then it calls it upon destruction (i.e. when leaving the scope).  The idea is that
    // you ignore it normally, and call `return pkt_updater.cancel();` on abnormal exit.
    struct Connection::pkt_tx_timer_updater
    {
      private:
        bool cancelled = false;
        Connection& conn;
        uint64_t ts;

      public:
        pkt_tx_timer_updater(Connection& c, uint64_t ts) : conn{c}, ts{ts} {}
        pkt_tx_timer_updater(pkt_tx_timer_updater&& x) = delete;
        pkt_tx_timer_updater(const pkt_tx_timer_updater& x) = delete;

        void cancel() { cancelled = true; }

        ~pkt_tx_timer_updater()
        {
            if (!cancelled)
                ngtcp2_conn_update_pkt_tx_time(conn, ts);
        }
    };

    // Sends the current `n_packets` packets queued in `send_buffer` with individual lengths
    // `send_buffer_size`.
    //
    // Returns true if the caller can keep on sending, false if the caller should return
    // immediately (i.e. because either an error occured or the socket is blocked).
    //
    // In the case where the socket is blocked, this sets up an event to wait for it to become
    // unblocked, at which point we'll re-enter flush_packets (which will finish off the pending
    // packets before continuing).
    //
    // If pkt_updater is provided then we cancel it when an error (other than a block) occurs.
    bool Connection::send(pkt_tx_timer_updater* pkt_updater)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(n_packets > 0 && n_packets <= MAX_BATCH);

        if (debug_datagram_counter_enabled)
        {
            debug_datagram_counter += n_packets;
            log::debug(log_cat, "enable_datagram_counter_test is true; sent packet count: {}", debug_datagram_counter);
        }

        auto rv = endpoint().send_packets(_path, send_buffer.data(), send_buffer_size.data(), send_ecn, n_packets);

        if (rv.blocked())
        {
            assert(n_packets > 0);  // n_packets, buf, bufsize now contain the unsent packets
            log::debug(log_cat, "Packet send blocked; queuing re-send");

            _endpoint.get_socket()->when_writeable([&ep = _endpoint, connid = reference_id(), this] {
                if (!ep.conns.count(connid))
                    return;  // Connection has gone away (and so `this` isn't valid!)

                if (send(nullptr))
                {  // Send finished so we can start our timers up again
                    packet_io_ready();
                }
                // Otherwise we're still blocked (or an error occured)
            });

            return false;
        }
        else if (rv.failure())
        {
            log::warning(log_cat, "Error while trying to send packet: {}", rv.str_error());
            if (pkt_updater)
                pkt_updater->cancel();

            log::debug(log_cat, "Endpoint deleting {}", reference_id());
            _endpoint.drop_connection(*this, io_error{CONN_SEND_FAIL});

            return false;
        }

        log::trace(log_cat, "Packets away!");
        return true;
    }

    // Don't worry about seeding this because it doesn't matter at all if the stream selection below
    // is predictable, we just want to shuffle it.
    thread_local std::mt19937 stream_start_rng{};

    void Connection::flush_packets(std::chrono::steady_clock::time_point tp)
    {
        // Maximum number of stream data packets to send out at once; if we reach this then we'll
        // schedule another event loop call of ourselves (so that we don't starve the loop)
        const auto max_udp_payload_size = ngtcp2_conn_get_path_max_tx_udp_payload_size(*this);
        const auto max_stream_packets = ngtcp2_conn_get_send_quantum(*this) / max_udp_payload_size;
        auto ts = static_cast<uint64_t>(std::chrono::nanoseconds{tp.time_since_epoch()}.count());

        if (n_packets > 0)
        {
            // We're blocked from a previous call, and haven't finished sending all our packets yet
            // so there's nothing to do for now (once the packets are fully sent we'll get called
            // again so that we can keep working on sending).
            log::debug(log_cat, "Skipping this flush_packets call; we still have {} queued packets", n_packets);
            return;
        }

        std::list<IOChannel*> channels;
        if (!_streams.empty())
        {
            // Start from a random stream so that we aren't favouring early streams by potentially
            // giving them more opportunities to send packets.
            auto mid = std::next(
                    _streams.begin(), std::uniform_int_distribution<size_t>{0, _streams.size() - 1}(stream_start_rng));

            for (auto it = mid; it != _streams.end(); ++it)
            {
                auto& stream_ptr = it->second;
                if (stream_ptr and not stream_ptr->_sent_fin)
                    channels.push_back(stream_ptr.get());
            }

            // if we have datagrams to send, then mix them into the streams
            if (datagrams && !datagrams->is_empty())
            {
                log::trace(log_cat, "Datagram channel has things to send");
                channels.push_back(datagrams.get());
            }

            for (auto it = _streams.begin(); it != mid; ++it)
            {
                auto& stream_ptr = it->second;
                if (stream_ptr and not stream_ptr->_sent_fin)
                    channels.push_back(stream_ptr.get());
            }
        }
        else if (datagrams && !datagrams->is_empty())
        {
            // if we have only datagrams to send, then we should probably do that
            log::trace(log_cat, "Datagram channel has things to send");
            channels.push_back(datagrams.get());
        }

        // This is our non-stream value (i.e. we give stream id -1 to ngtcp2 when we hit this).  We
        // hit it after we exhaust all streams (either they have nothing more to give, or we get
        // congested); it takes care of things like initial handshake packets, acks, and also
        // finishes off any partially-filled packet from any previous streams that didn't form a
        // complete packet.
        channels.push_back(pseudo_stream.get());
        auto streams_end_it = std::prev(channels.end());

        ngtcp2_pkt_info pkt_info{};
        auto* buf_pos = reinterpret_cast<uint8_t*>(send_buffer.data());
        pkt_tx_timer_updater pkt_updater{*this, ts};
        size_t stream_packets = 0;

        bool partially_filled = false;

        while (!channels.empty())
        {
            log::trace(log_cat, "Creating packet {} of max {} batch stream packets", n_packets, MAX_BATCH);
            bool datagram_waiting = false;
            ngtcp2_ssize nwrite = 0;
            ngtcp2_ssize ndatalen;
            uint32_t flags = 0;
            int64_t stream_id = -10;

            auto* source = channels.front();
            channels.pop_front();  // Pop it off; if this stream should be checked again, append just
                                   // before streams_end_it.

            // this block will execute all "real" streams plus the "pseudo stream" of ID -1 to finish
            // off any packets that need to be sent
            if (source->is_stream())
            {
                std::vector<ngtcp2_vec> bufs = source->pending();

                stream_id = source->stream_id();

                if (stream_id != -1)
                {
                    if (source->is_closing() && !source->sent_fin() && source->unsent() == 0)
                    {
                        log::trace(log_cat, "Sending FIN");
                        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                        source->set_fin(true);
                    }
                    else if (bufs.empty())
                    {
                        log::debug(log_cat, "pending() returned empty buffer for stream ID {}, moving on", stream_id);
                        continue;
                    }
                }

                nwrite = ngtcp2_conn_writev_stream(
                        *this,
                        _path,
                        &pkt_info,
                        buf_pos,
                        MAX_PMTUD_UDP_PAYLOAD,
                        &ndatalen,
                        flags |= NGTCP2_WRITE_STREAM_FLAG_MORE,
                        stream_id,
                        bufs.data(),
                        bufs.size(),
                        ts);

                log::trace(log_cat, "add_stream_data for stream {} returned [{},{}]", stream_id, nwrite, ndatalen);
            }
            else  // datagram block
            {
                // We try to pack in as many datagrams as we can into the packet in one shot (just like the
                // streams try to add as much stream data as they can).  We don't have to do this
                // (we could fall back to the outer loop), but that would somewhat starve datagram
                // throughput if there is a lot of contention with streams when there are lots of
                // relatively small datagrams.

                datagram_waiting = true;  // This will remain true only if we have datagrams pending
                                          // but accept none of them into the packet.
                for (;;)
                {
                    auto dgram = datagrams->pending_datagram(partially_filled);
                    if (!dgram)
                    {
                        datagram_waiting = false;
                        break;
                    }

                    int accepted = 0;
                    nwrite = ngtcp2_conn_writev_datagram(
                            *this,
                            _path,
                            &pkt_info,
                            buf_pos,
                            MAX_PMTUD_UDP_PAYLOAD,
                            &accepted,
                            flags |= NGTCP2_WRITE_DATAGRAM_FLAG_MORE,
                            dgram->id,
                            dgram->data(),
                            dgram->size(),
                            ts);

                    log::debug(log_cat, "ngtcp2_conn_writev_datagram returned a value of {}", nwrite);

                    if (accepted != 0)
                    {
                        log::trace(log_cat, "ngtcp2 accepted datagram ID: {} for transmission", dgram->id);
                        datagrams->confirm_datagram_sent();
                        datagram_waiting = false;
                    }
                    if (nwrite != NGTCP2_ERR_WRITE_MORE)
                        break;

                    partially_filled = true;
                }
            }

            // congested
            if (nwrite == 0)
            {
                bool congested = source->is_stream() && stream_id != -1;
                log::trace(
                        log_cat,
                        "Done writing: {}",
                        congested ? "connection is congested" : "nothing else to write right now");
                if (congested)
                {
                    // we are congested, so clear all pending streams (aside from the -1
                    // pseudo-stream at the end) so that our next call hits the -1 to finish off.
                    channels.erase(channels.begin(), streams_end_it);
                }
                continue;
            }

            if (nwrite < 0)
            {
                if (ngtcp2_err_is_fatal(nwrite))
                {
                    log::warning(
                            log_cat,
                            "Fatal ngtcp2 error: could not write frame - \"{}\" - closing connection...",
                            ngtcp2_strerror(nwrite));
                    _endpoint.close_connection(*this, io_error{(int)nwrite});
                    return;
                }
                if (nwrite == NGTCP2_ERR_WRITE_MORE)
                {
                    partially_filled = true;

                    if (source->is_stream())
                    {
                        log::trace(log_cat, "Consumed {} bytes from stream {} and have space left", ndatalen, stream_id);
                        assert(ndatalen >= 0);
                        if (stream_id != -1)
                            source->wrote(ndatalen);
                    }
                    else
                    {
                        if (source->has_unsent())
                            channels.push_front(datagrams.get());
                    }
                }
                else
                {
                    log::debug(log_cat, "Non-fatal ngtcp2 error (stream ID:{}): {}", stream_id, ngtcp2_strerror(nwrite));
                }

                continue;
            }

            partially_filled = false;

            if (stream_id > -1 && ndatalen > 0)
            {
                log::trace(log_cat, "consumed {} bytes from stream {}", ndatalen, stream_id);
                source->wrote(ndatalen);
            }

            // success
            buf_pos += nwrite;
            send_buffer_size[n_packets++] = nwrite;
            send_ecn = pkt_info.ecn;
            stream_packets++;

            if (n_packets == MAX_BATCH)
            {
                log::trace(log_cat, "Sending stream data packet batch");
                if (!send(&pkt_updater))
                    return;

                assert(n_packets == 0);
                buf_pos = reinterpret_cast<uint8_t*>(send_buffer.data());
            }

            if (stream_packets == max_stream_packets)
            {
                log::trace(log_cat, "Max stream packets ({}) reached", max_stream_packets);
                break;
            }

            // If the packet is full and we couldn't include any datagrams (despite having pending
            // ones) then we want to restart the next loop starting on datagrams to include that
            // datagram (so that big datagrams don't get starved out by small amounts of stream
            // data).
            if (datagram_waiting && nwrite > 0)
            {
                channels.push_front(datagrams.get());
                continue;
            }

            if (stream_id == -1 && channels.empty())
            {
                // For the -1 pseudo stream, we only exit once we get nwrite==0 above, so always
                // re-insert it if we get here.
                channels.push_back(source);
            }
            else if (source->has_unsent())
            {
                // For an actual stream with more data we want to let it be checked again, so
                // insert it just before the final -1 fake stream for potential reconsideration.
                assert(!channels.empty());
                channels.insert(streams_end_it, source);
            }
        }

        if (n_packets > 0)
        {
            log::trace(log_cat, "Sending final packet batch of {} packets", n_packets);
            send(&pkt_updater);
        }
        log::debug(log_cat, "Exiting flush_packets()");
    }

    void Connection::schedule_packet_retransmit(std::chrono::steady_clock::time_point ts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        ngtcp2_tstamp exp_ns = ngtcp2_conn_get_expiry(*this);

        if (exp_ns == std::numeric_limits<ngtcp2_tstamp>::max())
        {
            log::debug(log_cat, "No retransmit needed right now");
            event_del(packet_retransmit_timer.get());
            return;
        }

        auto delta = static_cast<int64_t>(exp_ns) * 1ns - ts.time_since_epoch();
        log::trace(log_cat, "Expiry delta: {}ns", delta.count());

        // very rarely, something weird happens and the wakeup time ngtcp2 gives is
        // in the past; if that happens, fire the timer with a 0µs timeout.
        timeval tv;
        if (delta > 0s)
        {
            delta += 999ns;  // Round up to the next µs (libevent timers have µs precision)
            tv.tv_sec = delta / 1s;
            tv.tv_usec = (delta % 1s) / 1us;
        }
        else
        {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
        }
        event_add(packet_retransmit_timer.get(), &tv);
    }

    int Connection::stream_opened(int64_t id)
    {
        log::trace(log_cat, "New stream ID:{}", id);

        if (auto itr = _stream_queue.find(id); itr != _stream_queue.end())
        {
            log::debug(log_cat, "Taking ready stream from on deck and assigning stream ID {}!", id);

            auto& s = itr->second;
            s->set_ready();

            [[maybe_unused]] auto [it, ins] = _streams.emplace(id, std::move(s));
            _stream_queue.erase(itr);
            assert(ins);
            return 0;
        }

        auto stream = construct_stream(nullptr, id);

        stream->_stream_id = id;
        stream->set_ready();

        log::debug(log_cat, "Local endpoint creating stream to match remote");

        if (uint64_t app_err_code = context->stream_open_cb ? context->stream_open_cb(*stream) : 0; app_err_code != 0)
        {
            log::info(log_cat, "stream_open_callback returned error code {}, closing stream {}", app_err_code, id);
            assert(endpoint().in_event_loop());
            stream->close(app_err_code);
            return 0;
        }

        [[maybe_unused]] auto [it, ins] = _streams.emplace(id, std::move(stream));
        assert(ins);
        log::info(log_cat, "Created new incoming stream {}", id);
        return 0;
    }

    void Connection::stream_execute_close(Stream& stream, uint64_t app_code)
    {
        const bool was_closing = stream._is_closing;
        stream._is_closing = stream._is_shutdown = true;

        if (stream._is_watermarked)
            stream.clear_watermarks();

        if (!was_closing)
        {
            log::trace(log_cat, "Invoking stream close callback");
            stream.closed(app_code);
        }
    }

    void Connection::stream_closed(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        log::info(log_cat, "Stream (ID:{}) closed with code {}", id, app_code);
        auto it = _streams.find(id);

        if (it == _streams.end())
            return;

        auto& stream = *it->second;
        stream_execute_close(stream, app_code);

        _streams.erase(it);
        log::trace(log_cat, "Stream (ID:{}) erased", id);

        if (!ngtcp2_conn_is_local_stream(*this, id))
            ngtcp2_conn_extend_max_streams_bidi(*this, 1);

        packet_io_ready();
    }

    // Called during connection closing (immediately before the connection close callback) to fire
    // stream close callbacks for all open streams.
    void Connection::close_all_streams()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        for (const auto& [id, stream] : _stream_queue)
            stream_execute_close(*stream, STREAM_ERROR_CONNECTION_CLOSED);
        _stream_queue.clear();
        for (const auto& s : pending_streams)
            stream_execute_close(*s, STREAM_ERROR_CONNECTION_CLOSED);
        pending_streams.clear();

        while (!_streams.empty())
            stream_closed(_streams.begin()->first, STREAM_ERROR_CONNECTION_CLOSED);
    }

    void Connection::drop_streams()
    {
        log::debug(log_cat, "Dropping all streams from Connection {}", reference_id());
        for (auto* stream_map : {&_streams, &_stream_queue})
        {
            for (auto& [id, stream] : *stream_map)
                stream->_conn = nullptr;
            stream_map->clear();
        }
        for (auto& stream : pending_streams)
            stream->_conn = nullptr;
        pending_streams.clear();
        if (datagrams)
        {
            datagrams->_conn = nullptr;
            datagrams.reset();
        }
        if (pseudo_stream)
        {
            pseudo_stream->_conn = nullptr;
            pseudo_stream.reset();
        }
    }

    int Connection::stream_ack(int64_t id, size_t size)
    {
        if (auto it = _streams.find(id); it != _streams.end())
        {
            it->second->acknowledge(size);
            return 0;
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int Connection::stream_receive(int64_t id, bspan data, bool fin)
    {
        auto str = get_stream(id);

        if (data.size() == 0)
        {
            log::debug(
                    log_cat,
                    "Stream (ID: {}) received empty fin frame, bypassing user-supplied data callback",
                    str->_stream_id);
            return 0;
        }

        log::trace(log_cat, "Stream (ID: {}) received data: {}", id, buffer_printer{data});

        std::optional<uint64_t> error;
        try
        {
            str->receive(data);
        }
        catch (const application_stream_error& e)
        {
            // Application threw us a custom error code to close the stream with
            log::debug(
                    log_cat,
                    "Stream {} data callback threw us a custom error code ({}); closing stream",
                    str->_stream_id,
                    e.code);
            error = e.code;
        }
        catch (const std::exception& e)
        {
            log::warning(
                    log_cat,
                    "Stream {} data callback raised exception ({}); closing stream with {}",
                    str->_stream_id,
                    e.what(),
                    quic_strerror(STREAM_ERROR_EXCEPTION));
            error = STREAM_ERROR_EXCEPTION;
        }
        catch (...)
        {
            log::warning(
                    log_cat,
                    "Stream {} data callback raised an unknown exception; closing stream with {}",
                    str->_stream_id,
                    quic_strerror(STREAM_ERROR_EXCEPTION));
            error = STREAM_ERROR_EXCEPTION;
        }
        if (error)
        {
            str->close(*error);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        if (fin)
        {
            log::info(log_cat, "Stream {} closed by remote", str->_stream_id);
            // no clean up, close_cb called after this
        }
        else
        {
            if (str->_paused)
                str->_paused_offset += data.size();
            else
                ngtcp2_conn_extend_max_stream_offset(*this, id, data.size());
            ngtcp2_conn_extend_max_offset(*this, data.size());
        }

        return 0;
    }

    // this callback is defined for debugging datagrams
    int Connection::ack_datagram(uint64_t dgram_id)
    {
        log::trace(log_cat, "Connection (CID: {}) acked datagram ID:{}", _source_cid, dgram_id);
        return 0;
    }

    int Connection::recv_datagram(bspan data, bool fin)
    {
        log::trace(log_cat, "Connection (CID: {}) received datagram: {}", _source_cid, buffer_printer{data});

        assert(datagrams);  // This callback shouldn't have been set up if we don't have datagrams

        std::optional<std::vector<std::byte>> maybe_data;

        if (_packet_splitting)
        {
            if (data.size() < 2)
            {
                log::warning(log_cat, "Ignoring invalid datagram: too short for packet splitting");
                return 0;
            }

            uint16_t dgid = oxenc::load_big_to_host<uint16_t>(data.data());
            data = data.subspan(2);

            if (dgid % 4 == 0)
                log::trace(log_cat, "Datagram sent unsplit, bypassing rotating buffer");
            else
            {
                // send received datagram to rotating_buffer if packet_splitting is enabled
                maybe_data = datagrams->to_buffer(data, dgid);

                // split datagram did not have a match
                if (not maybe_data)
                {
                    log::trace(log_cat, "Datagram (ID: {}) awaiting counterpart", dgid);
                    return 0;
                }
            }
        }

        if (!datagrams->dgram_data_cb)
            log::trace(log_cat, "Connection (CID: {}) has no endpoint-supplied datagram data callback", _source_cid);
        else
        {
            bool good = false;

            try
            {
                // FIXME TODO: this is performing an allocation and copy for *every* small datagram
                // (every datagram when splitting disabled), to optimize the case where a split
                // datagram recipient wants to transfer an owned buffer of a recombined split
                // packet.  This is *only* going to be preferable in a case where the callback
                // always wants to make a copy anyway, and is going to be *always* worse for
                // non-storing callbacks.
                //
                // We should ideally perhaps have *two* datagram callbacks: one that always copies
                // (i.e. this one) and one that takes a span for cases where the span callback
                // doesn't need to copy.

                datagrams->dgram_data_cb(
                        *di, (maybe_data ? std::move(*maybe_data) : std::vector<std::byte>{data.begin(), data.end()}));
                good = true;
            }
            catch (const std::exception& e)
            {
                log::warning(
                        log_cat,
                        "Connection (CID: {}) raised exception ({}); closing connection with app code {}",
                        _source_cid,
                        e.what(),
                        DATAGRAM_ERROR_EXCEPTION);
            }
            catch (...)
            {
                log::warning(
                        log_cat,
                        "Connection (CID: {}) raised unknown exception; closing connection with app code {}",
                        _source_cid,
                        DATAGRAM_ERROR_EXCEPTION);
            }
            if (!good)
            {
                log::debug(log_cat, "Endpoint closing {}", reference_id());
                _endpoint.close_connection(*this, io_error{DATAGRAM_ERROR_EXCEPTION});
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }

        if (fin)
        {
            log::debug(log_cat, "Connection (CID: {}) received FIN from remote", _source_cid);
            // TODO: no clean up, as close cb is called after? Or just for streams
        }

        return 0;
    }

    std::string_view Connection::selected_alpn() const
    {
        return _endpoint.call_get([this]() { return get_session()->selected_alpn(); });
    }

    void Connection::send_datagram(bspan data, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!datagrams)
            throw std::runtime_error{"Connection not configured for datagram IO"};

        datagrams->send(data, std::move(keep_alive));
    }

    uint64_t Connection::get_streams_available_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return ngtcp2_conn_get_streams_bidi_left(*this);
    }

    size_t Connection::get_max_datagram_piece()
    {
        if (!datagrams)
            return 0;

        // We have general quic packet overhead, plus packet splitting adds another 2 bytes of
        // overhead per datagram piece:
        size_t adjustment = (_early_data ? DATAGRAM_OVERHEAD_0RTT : DATAGRAM_OVERHEAD_1RTT) + (_packet_splitting ? 2 : 0);

        size_t max_dgram_piece = ngtcp2_conn_get_path_max_tx_udp_payload_size(*this) - adjustment;
        if (max_dgram_piece != _last_max_dgram_piece)
        {
            _max_dgram_size_changed = true;
            _last_max_dgram_piece = max_dgram_piece;
        }

        return max_dgram_piece;
    }
    size_t Connection::get_max_datagram_size_impl()
    {
        return get_max_datagram_piece() * (_packet_splitting ? 2 : 1);
    }
    bool Connection::datagrams_enabled() const
    {
        return static_cast<bool>(datagrams);
    }
    void Connection::set_split_datagram_lookahead(int n)
    {
        if (datagrams)
            datagrams->set_split_datagram_lookahead(n);
    }
    int Connection::get_split_datagram_lookahead() const
    {
        return datagrams ? datagrams->get_split_datagram_lookahead() : -1;
    }

    std::optional<size_t> Connection::max_datagram_size_changed()
    {
        if (!_max_dgram_size_changed)
            return std::nullopt;
        return _endpoint.call_get([this]() -> std::optional<size_t> {
            // Check it again via an exchange, in case someone raced us here
            if (_max_dgram_size_changed.exchange(false))
                return _last_max_dgram_piece * (_packet_splitting ? 2 : 1);
            return std::nullopt;
        });
    }

    void Connection::init(
            ngtcp2_settings& settings,
            ngtcp2_transport_params& params,
            ngtcp2_callbacks& callbacks,
            std::chrono::nanoseconds handshake_timeout)
    {
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.path_validation = connection_callbacks::on_path_validation;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = connection_callbacks::on_recv_stream_data;
        callbacks.acked_stream_data_offset = connection_callbacks::on_acked_stream_data_offset;
        callbacks.stream_close = connection_callbacks::on_stream_close;
        callbacks.extend_max_local_streams_bidi = connection_callbacks::extend_max_local_streams_bidi;
        callbacks.rand = connection_callbacks::rand_cb;
        callbacks.get_new_connection_id = connection_callbacks::get_new_connection_id;
        callbacks.remove_connection_id = connection_callbacks::remove_connection_id;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.stream_reset = connection_callbacks::on_stream_reset;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.stream_open = connection_callbacks::on_stream_open;
        callbacks.handshake_completed = connection_callbacks::on_handshake_completed;

        callbacks.recv_stateless_reset = connection_callbacks::recv_stateless_reset;
        callbacks.dcid_status = connection_callbacks::on_connection_id_status;

        ngtcp2_settings_default(&settings);

        settings.initial_ts = get_timestamp().count();
#ifndef NDEBUG
        settings.log_printf = log_printer;
#endif
        settings.max_tx_udp_payload_size = MAX_PMTUD_UDP_PAYLOAD;
        settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
        settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
        settings.max_window = 24_Mi;
        settings.max_stream_window = 16_Mi;
        settings.handshake_timeout = handshake_timeout <= 0s ? UINT64_MAX : static_cast<uint64_t>(handshake_timeout.count());

        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 15_Mi;
        // Max concurrent streams supported on one connection
        params.initial_max_streams_uni = 0;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to us)
        params.initial_max_stream_data_bidi_local = 6_Mi;
        params.initial_max_stream_data_bidi_remote = 6_Mi;
        params.initial_max_stream_data_uni = 6_Mi;
        params.max_idle_timeout = std::chrono::nanoseconds{context->config.idle_timeout}.count();
        params.active_connection_id_limit = MAX_ACTIVE_CIDS;

        // config values
        params.initial_max_streams_bidi = _max_streams;

        if (datagrams)
        {
            log::trace(log_cat, "Enabling datagram support for connection");
            // This is effectively an "unlimited" value, which lets us accept any size that fits into a QUIC packet
            // (see rfc 9221)
            params.max_datagram_frame_size = 65535;
            // default ngtcp2 values set by ngtcp2_settings_default_versioned
            params.max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;  // 65527
            settings.max_tx_udp_payload_size = MAX_PMTUD_UDP_PAYLOAD;                // 1500 - 48 (approximate overhead)
            // settings.no_tx_udp_payload_size_shaping = 1;
            callbacks.recv_datagram = connection_callbacks::on_recv_datagram;
#ifndef NDEBUG
            callbacks.ack_datagram = connection_callbacks::on_ack_datagram;
#endif

            di = _endpoint.make_shared<dgram_interface>(*this);
        }
        else
        {
            // setting this value to 0 disables datagram support
            params.max_datagram_frame_size = 0;
            callbacks.recv_datagram = nullptr;
        }
    }

    Connection::Connection(
            Endpoint& ep,
            ConnectionID rid,
            const quic_cid& scid,
            const quic_cid& dcid,
            const Path& path,
            std::shared_ptr<IOContext> ctx,
            std::span<const std::string> alpns,
            std::chrono::nanoseconds default_handshake_timeout,
            std::optional<std::vector<unsigned char>> remote_pk,
            ngtcp2_pkt_hd* hdr,
            std::optional<ngtcp2_token_type> token_type,
            ngtcp2_cid* ocid) :
            _endpoint{ep},
            context{std::move(ctx)},
            dir{context->dir},
            _is_outbound{dir == Direction::OUTBOUND},
            _ref_id{rid},
            _source_cid{scid},
            _dest_cid{dcid},
            _path{path},
            _max_streams{context->config.max_streams ? context->config.max_streams : DEFAULT_MAX_BIDI_STREAMS},
            _packet_splitting{context->config.split_packet},
            tls_creds{context->tls_creds}
    {
        // If a connection_{established/closed}_callback was passed to IOContext via `Endpoint::{listen,connect}(...)`...
        //  - If this is an outbound, steal the callback to be used once. Outbound connections
        //    generate a new IOContext for each call to `::connect(...)`
        //  - If this is an inbound, do not steal the callback. Inbound connections all share
        //    the same IOContext, so we want to re-use the same callback
        conn_established_cb = (context->conn_established_cb)
                                    ? is_outbound() ? std::move(context->conn_established_cb) : context->conn_established_cb
                                    : nullptr;
        conn_closed_cb = (context->conn_closed_cb)
                               ? is_outbound() ? std::move(context->conn_closed_cb) : context->conn_closed_cb
                               : nullptr;

        if (context->config.datagram_support)
            datagrams = _endpoint.make_shared<DatagramIO>(
                    *this, _endpoint, context->dgram_data_cb ? context->dgram_data_cb : ep.dgram_recv_cb);
        pseudo_stream = _endpoint.make_shared<Stream>(*this, _endpoint);
        pseudo_stream->_stream_id = -1;

        const auto d_str = is_outbound() ? "outbound" : "inbound";
        log::trace(log_cat, "Creating new {} connection object", d_str);

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;
        int conn_new_rv = 0;

        auto handshake_timeout = context->config.handshake_timeout.value_or(default_handshake_timeout);

        init(settings, params, callbacks, handshake_timeout);

        // Clients should be the ones providing a remote pubkey here. This way we can emplace it into
        // the gnutlssession object to be verified. Servers should be verifying via callback
        std::optional<std::span<const unsigned char>> expected_pubkey;
        if (is_outbound())
        {
            if (!remote_pk.has_value())
                throw std::logic_error{"No remote pubkey provided for outbound connection key verification"};
            remote_pubkey = std::move(*remote_pk);
            expected_pubkey.emplace(remote_pubkey);
            log::debug(
                    log_cat,
                    "Outbound connection configured for key verification, expecting pubkey {}",
                    oxenc::to_hex(remote_pubkey.begin(), remote_pubkey.end()));
        }
        else if (remote_pk.has_value())
        {
            throw std::logic_error{"Remote pubkey may not be provided for inbound connections"};
        }

        tls_session = tls_creds->make_session(*this, *context, alpns, expected_pubkey);

        if (is_outbound())
        {
            callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
            callbacks.handshake_confirmed = connection_callbacks::on_handshake_confirmed;
            callbacks.recv_retry = connection_callbacks::on_recv_retry;
            callbacks.recv_new_token = connection_callbacks::on_recv_token;
            callbacks.tls_early_data_rejected = connection_callbacks::on_early_data_rejected;

            auto maybe_token = _endpoint.get_path_validation_token(_path.remote);

            if (maybe_token)
            {
                settings.token = maybe_token->data();
                settings.tokenlen = maybe_token->size();
            }

            conn_new_rv = ngtcp2_conn_client_new(
                    &connptr,
                    &_dest_cid,
                    &_source_cid,
                    path,
                    NGTCP2_PROTO_VER_V1,
                    &callbacks,
                    &settings,
                    &params,
                    nullptr,
                    this);
        }
        else
        {
            callbacks.recv_client_initial = connection_callbacks::on_recv_client_initial;

            if (ocid)
            {
                params.original_dcid = *ocid;
                params.retry_scid = ngtcp2_cid{hdr->dcid};
                params.retry_scid_present = 1;
            }
            else
            {
                params.original_dcid = ngtcp2_cid{hdr->dcid};
            }

            params.original_dcid_present = 1;
            settings.token = hdr->token;
            settings.tokenlen = hdr->tokenlen;

            // For a server the reset token for the initial (sequence 0) cid that we give back to
            // the client to use has its associated reset token carried in the transport parameters
            // sent back to the client:
            params.stateless_reset_token_present = 1;
            _endpoint.generate_reset_token(_source_cid, params.stateless_reset_token);
            log::trace(
                    log_cat,
                    "Generated transport parameter reset token {} for initial scid {}",
                    oxenc::to_hex(std::begin(params.stateless_reset_token), std::end(params.stateless_reset_token)),
                    _source_cid);

            if (token_type)
                settings.token_type = *token_type;

            conn_new_rv = ngtcp2_conn_server_new(
                    &connptr,
                    &_dest_cid,
                    &_source_cid,
                    path,
                    NGTCP2_PROTO_VER_V1,
                    &callbacks,
                    &settings,
                    &params,
                    nullptr,
                    this);
        }

        if (conn_new_rv != 0)
        {
            log::critical(
                    log_cat, "Error: failed to initialize {} ngtcp2 connection: {}", d_str, ngtcp2_strerror(conn_new_rv));
            throw std::runtime_error{"Failed to initialize connection object: "s + ngtcp2_strerror(conn_new_rv)};
        }

        ngtcp2_conn_set_keep_alive_timeout(connptr, std::chrono::nanoseconds{context->config.keep_alive}.count());

        tls_session->conn_ref.get_conn = get_conn;
        tls_session->conn_ref.user_data = this;
        ngtcp2_conn_set_tls_native_handle(connptr, tls_session->get_session());

        conn.reset(connptr);

        if (is_outbound() && tls_creds->outbound_0rtt())
        {
            // If the tls session hook extracted session data then it will have stashed the
            // transport params data here for us to grab:
            if (auto tp_data = tls_session->extract_0rtt_tp_data())
            {
                if (int err = ngtcp2_conn_decode_and_set_0rtt_transport_params(connptr, tp_data->data(), tp_data->size());
                    err == 0)
                {
                    log::debug(log_cat, "transport parameters successfully loaded for 0-RTT connection support");
                    _early_data = true;
                    if (datagrams)
                        datagrams->early_data_begin();
                }
                else
                    log::warning(
                            log_cat,
                            "Failed to decode and set 0rtt QUIC transport params ({}); this connection will not use "
                            "0-RTT",
                            ngtcp2_strerror(err));
            }
            else
                log::debug(log_cat, "no transport param data for this connection; 0-RTT will not engage");
        }

        auto* ev_base = endpoint().get_loop().get();

        packet_io_trigger.reset(event_new(
                ev_base,
                -1,
                0,
                [](evutil_socket_t, short, void* self) { static_cast<Connection*>(self)->on_packet_io_ready(); },
                this));
        packet_retransmit_timer.reset(event_new(
                ev_base,
                -1,
                0,
                [](evutil_socket_t, short, void* self_) {
                    auto& self = *static_cast<Connection*>(self_);
                    if (auto rv = ngtcp2_conn_handle_expiry(self, get_timestamp().count()); rv != 0)
                    {
                        log::debug(log_cat, "Error: expiry handler invocation returned error code: {}", ngtcp2_strerror(rv));
                        self.endpoint().close_connection(self, io_error{rv});
                        return;
                    }
                    self.on_packet_io_ready();
                },
                this));

        event_add(packet_retransmit_timer.get(), nullptr);

        log::info(log_cat, "Successfully created new {} connection object {}", d_str, _ref_id);
    }

    std::shared_ptr<Connection> Connection::make_conn(
            Endpoint& ep,
            ConnectionID rid,
            const quic_cid& scid,
            const quic_cid& dcid,
            const Path& path,
            std::shared_ptr<IOContext> ctx,
            std::span<const std::string> alpns,
            std::chrono::nanoseconds default_handshake_timeout,
            std::optional<std::vector<unsigned char>> remote_pk,
            ngtcp2_pkt_hd* hdr,
            std::optional<ngtcp2_token_type> token_type,
            ngtcp2_cid* ocid)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        std::shared_ptr<Connection> conn{new Connection{
                ep,
                rid,
                scid,
                dcid,
                path,
                std::move(ctx),
                alpns,
                default_handshake_timeout,
                remote_pk,
                hdr,
                token_type,
                ocid}};

        conn->packet_io_ready();

        if (conn->is_outbound())
            ep.initial_association(*conn);

        return conn;
    }

    void Connection::check_stream_timeouts()
    {
        for (const auto* s : {&_streams, &_stream_queue})
            for (const auto& [id, stream] : *s)
                stream->check_timeouts();
        for (const auto& s : pending_streams)
            s->check_timeouts();
    }

    size_t connection_interface::num_streams_active()
    {
        return endpoint().call_get([this] { return num_streams_active_impl(); });
    }
    size_t connection_interface::num_streams_pending()
    {
        return endpoint().call_get([this] { return num_streams_pending_impl(); });
    }
    uint64_t connection_interface::get_max_streams()
    {
        return endpoint().call_get([this] { return get_max_streams_impl(); });
    }
    uint64_t connection_interface::get_streams_available()
    {
        return endpoint().call_get([this] { return get_streams_available_impl(); });
    }
    Path connection_interface::path()
    {
        return endpoint().call_get([this]() -> Path { return path_impl(); });
    }
    Address connection_interface::local()
    {
        return endpoint().call_get([this]() -> Address { return local_impl(); });
    }
    Address connection_interface::remote()
    {
        return endpoint().call_get([this]() -> Address { return remote_impl(); });
    }
    size_t connection_interface::get_max_datagram_size()
    {
        return endpoint().call_get([this]() { return get_max_datagram_size_impl(); });
    }

    connection_interface::~connection_interface()
    {
        log::trace(log_cat, "connection_interface @{} destroyed", (void*)this);
    }

    Connection::~Connection()
    {
        log::trace(log_cat, "Connection @{} destroyed", (void*)this);
    }

}  // namespace oxen::quic
