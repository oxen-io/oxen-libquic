#include "connection.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>

#include "datagram.hpp"
#include "endpoint.hpp"
#include "error.hpp"
#include "format.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"
#include "stream.hpp"
#include "utils.hpp"

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
    // importantly, because `Callbacks` is a friend-with-benefits of Endpoint that can touch its
    // privates.
    struct Callbacks
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

        static int on_stream_stop_sending(
                ngtcp2_conn* /* conn */,
                int64_t stream_id,
                uint64_t app_error_code,
                void* user_data,
                void* /* stream_user_data */)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            static_cast<Connection*>(user_data)->stream_stop_sending(stream_id, app_error_code);
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
            static_cast<Connection*>(user_data)->stream_reset(stream_id, app_error_code);
            return 0;
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
                uint64_t /* seq */,
                const ngtcp2_cid* cid,
                const uint8_t* /* token */,
                void* user_data)
        {
            auto* conn = static_cast<Connection*>(user_data);

            auto dir_str = conn->is_inbound() ? "SERVER"s : "CLIENT"s;
            auto action = type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE ? "ACTIVATING"s : "DEACTIVATING"s;
            log::trace(log_cat, "{} {} DCID:{}", dir_str, action, oxenc::to_hex(cid->data, cid->data + cid->datalen));

            // auto& ep = conn->endpoint();

            switch (type)
            {
                case NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE:
                    // ep.associate_cid(cid, *conn);
                    break;
                case NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE:
                    // ep.dissociate_cid(cid, *conn);
                    break;
                default:
                    break;
            }

            return 0;
        }

        static int get_new_connection_id(
                ngtcp2_conn* /* _conn */, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;

            cid->datalen = cidlen;
            auto* conn = static_cast<Connection*>(user_data);
            auto& ep = conn->endpoint();

            if (ngtcp2_crypto_generate_stateless_reset_token(
                        token, ep._static_secret.data(), ep._static_secret.size(), cid) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;

            auto dir_str = conn->is_outbound() ? "CLIENT"s : "SERVER"s;
            log::trace(log_cat, "{} generated new CID for {}", dir_str, conn->reference_id());
            ep.associate_cid(cid, *conn);

            // TODO: send new stateless reset token
            //  write packet using ngtcp2_pkt_write_stateless_reset
            //  define recv_stateless_reset for client
            //  set stateless_reset_present in transport params

            return 0;
        }

        static int remove_connection_id(ngtcp2_conn* /* _conn */, const ngtcp2_cid* cid, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto* conn = static_cast<Connection*>(user_data);
            auto dir_str = conn->is_outbound() ? "CLIENT"s : "SERVER"s;
            log::trace(log_cat, "{} dissociating CID for {}", dir_str, conn->reference_id());
            conn->endpoint().dissociate_cid(cid, *conn);

            return 0;
        }

        static int extend_max_local_streams_bidi(
                [[maybe_unused]] ngtcp2_conn* _conn, uint64_t /*max_streams*/, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto& conn = *static_cast<Connection*>(user_data);
            assert(_conn == conn);

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

            if (conn.is_outbound())
            {
                log::trace(log_cat, "Client updating remote addr...");
                conn.set_remote_addr(path->remote);

                return 0;
            }
            else if (res != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS)
            {
                log::debug(log_cat, "Path validation unsuccessful!");
                return 0;
            }
            else if (not(flags & NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN))
            {
                log::debug(log_cat, "Path validation successful!");
                return 0;
            }
            else
                return conn.server_path_validation(path);
        }

        static int on_early_data_rejected(ngtcp2_conn* _conn, void* user_data)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto& conn = *static_cast<Connection*>(user_data);
            assert(_conn == conn);

            (void)conn;
            (void)_conn;

            return 0;
        }
    };

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
        assert(not remote_pubkey.empty());
        _endpoint.store_path_validation_token(remote_pubkey, {token, tokenlen});
        return 0;
    }

    int Connection::server_path_validation(const ngtcp2_path* path)
    {
        assert(is_inbound());
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

        if (auto rv = ngtcp2_conn_submit_new_token(conn.get(), token.data(), len); rv != 0)
        {
            log::error(log_cat, "ngtcp2_conn_submit_new_token failed: {}", ngtcp2_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        log::debug(log_cat, "Server completed path validation!");
        return 0;
    }

    int Connection::client_handshake_completed()
    {
        /** TODO:
            This section will be uncommented and finished upon completion of 0RTT and session resumption capabilities.
                - If early data is NOT ACCEPTED, then the call to ngtcp2_conn_tls_early_data_rejected must be invoked
                to reset aspects of connection state prior to early data rejection.
                - If early data is ACCEPTED, then we can open streams and start doing things immediately. At that point,
                we should encode and store 0RTT transport parameters.
            Moreover, decoding and setting 0RTT transport parameters must be handled in connection creation. Both that
            location and the required callbacks are comment-blocked in the relevant location.
        */
        // if (not tls_session->get_early_data_accepted())
        //{
        // log::info(log_cat, "Early data was rejected by server!");

        // if (auto rv = ngtcp2_conn_tls_early_data_rejected(conn.get()); rv != 0)
        // {
        //     log::error(log_cat, "ngtcp2_conn_tls_early_data_rejected: {}", ngtcp2_strerror(rv));
        //     return -1;
        // }
        //}

        // ustring data;
        // data.resize(256);

        // if (auto len = ngtcp2_conn_encode_0rtt_transport_params(conn.get(), data.data(), data.size()); len > 0)
        // {
        //     _endpoint.store_0rtt_transport_params(remote_pubkey, data);
        //     log::info(log_cat, "Client encoded and stored 0rtt transport params");
        // }
        // else
        // {
        //     log::warning(log_cat, "Client could not encode 0-RTT transport parameters: {}", ngtcp2_strerror(len));
        // }

        return 0;
    }

    int Connection::server_handshake_completed()
    {
        // TODO: uncomment this when 0rtt is implemented
        // tls_session->send_session_ticket();

        auto path = ngtcp2_conn_get_path(conn.get());
        auto now = get_timestamp().count();

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

        if (auto rv = ngtcp2_conn_submit_new_token(conn.get(), token.data(), len); rv != 0)
        {
            log::error(log_cat, "ngtcp2_conn_submit_new_token failed: {}", ngtcp2_strerror(rv));
            return -1;
        }

        return 0;
    }

    void Connection::set_validated()
    {
        _is_validated = true;

        if (is_inbound())
            remote_pubkey = dynamic_cast<GNUTLSSession*>(get_session())->remote_key();
    }

    int Connection::last_cleared() const
    {
        return datagrams->recv_buffer.last_cleared;
    }

    void Connection::early_data_rejected()
    {
        close_connection();
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

    ustring_view Connection::remote_key() const
    {
        return remote_pubkey;
    }

    TLSSession* Connection::get_session() const
    {
        return tls_session.get();
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
                _endpoint.call([this]() {
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
                _endpoint.call([this, rv]() {
                    log::debug(log_cat, "Endpoint deleting {}", reference_id());
                    _endpoint.drop_connection(*this, io_error{rv});
                });
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
                _endpoint.call([this, rv]() {
                    log::debug(log_cat, "Endpoint deleting {}", reference_id());
                    _endpoint.drop_connection(*this, io_error{rv});
                });
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
    // so, we move them to the streams map, where they will get picked up by flush_streams and dump
    // their buffers. If none are ready, we keep chugging along and make another stream as usual. Though
    // if none of the pending streams are ready, the new stream really shouldn't be ready, but here we are
    void Connection::check_pending_streams(uint64_t available)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint64_t popped = 0;

        while (!pending_streams.empty() && popped < available)
        {
            auto& str = pending_streams.front();

            if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &str->_stream_id, str.get()); rv == 0)
            {
                log::debug(log_cat, "Stream [ID:{}] ready for broadcast, moving out of pending streams", str->_stream_id);
                str->set_ready();
                popped += 1;
                _streams[str->_stream_id] = std::move(str);
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

            if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &stream->_stream_id, stream.get()); rv != 0)
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
    // unblocked, at which point we'll re-enter flush_streams (which will finish off the pending
    // packets before continuing).
    //
    // If pkt_updater is provided then we cancel it when an error (other than a block) occurs.
    bool Connection::send(pkt_tx_timer_updater* pkt_updater)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(n_packets > 0 && n_packets <= MAX_BATCH);

        if (debug_datagram_flip_flop_enabled)
        {
            debug_datagram_counter += n_packets;
            log::debug(log_cat, "enable_datagram_flip_flop_test is true; sent packet count: {}", debug_datagram_counter);
        }

        auto rv = endpoint().send_packets(_path, send_buffer.data(), send_buffer_size.data(), send_ecn, n_packets);

        if (rv.blocked())
        {
            assert(n_packets > 0);  // n_packets, buf, bufsize now contain the unsent packets
            log::debug(log_cat, "Packet send blocked; queuing re-send");

            _endpoint.get_socket()->when_writeable([this] {
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

            _endpoint.call([this]() {
                log::debug(log_cat, "Endpoint deleting {}", reference_id());
                _endpoint.drop_connection(*this, io_error{CONN_SEND_FAIL});
            });

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
        const auto max_udp_payload_size = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn.get());
        const auto max_stream_packets = ngtcp2_conn_get_send_quantum(conn.get()) / max_udp_payload_size;
        auto ts = static_cast<uint64_t>(std::chrono::nanoseconds{tp.time_since_epoch()}.count());

        if (n_packets > 0)
        {
            // We're blocked from a previous call, and haven't finished sending all our packets yet
            // so there's nothing to do for now (once the packets are fully sent we'll get called
            // again so that we can keep working on sending).
            log::debug(log_cat, "Skipping this flush_streams call; we still have {} queued packets", n_packets);
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
            if (not datagrams->is_empty())
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
        else if (not datagrams->is_empty())
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

        bool prefer_big_first{true};

        while (!channels.empty())
        {
            log::trace(log_cat, "Creating packet {} of max {} batch stream packets", n_packets, MAX_BATCH);
            int datagram_accepted = std::numeric_limits<int>::min();
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
                        log::trace(log_cat, "pending() returned empty buffer for stream ID {}, moving on", stream_id);
                        continue;
                    }
                }

                nwrite = ngtcp2_conn_writev_stream(
                        conn.get(),
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
                auto dgram = source->pending_datagram(prefer_big_first);

                nwrite = ngtcp2_conn_writev_datagram(
                        conn.get(),
                        _path,
                        &pkt_info,
                        buf_pos,
                        MAX_PMTUD_UDP_PAYLOAD,
                        &datagram_accepted,
                        flags |= NGTCP2_WRITE_DATAGRAM_FLAG_MORE,
                        dgram.id,
                        dgram.data(),
                        dgram.size(),
                        ts);

                log::trace(log_cat, "ngtcp2_conn_writev_datagram returned a value of {}", nwrite);

                if (datagram_accepted != 0)
                {
                    log::trace(log_cat, "ngtcp2 accepted datagram ID: {} for transmission", dgram.id);
                    datagrams->send_buffer.drop_front(prefer_big_first);
                }
            }

            // congested
            if (nwrite == 0)
            {
                log::trace(log_cat, "Done writing: connection is congested");
                if (source->is_stream() && stream_id != -1)
                    // we are congested, so clear all pending streams (aside from the -1
                    // pseudo-stream at the end) so that our next call hits the -1 to finish off.
                    channels.erase(channels.begin(), streams_end_it);
                continue;
            }

            if (nwrite < 0)
            {
                if (ngtcp2_err_is_fatal(nwrite))
                {
                    log::critical(log_cat, "Fatal ngtcp2 error: could not write frame - \"{}\"", ngtcp2_strerror(nwrite));
                    _endpoint.close_connection(*this, io_error{(int)nwrite});
                    return;
                }
                if (nwrite == NGTCP2_ERR_WRITE_MORE)
                {
                    // lets try fitting a small end of a split datagram in
                    prefer_big_first = false;

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

            prefer_big_first = true;

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

            // packet is full and the datagram was NOT included, so it must be written to the next packet
            if (datagram_accepted == 0 && nwrite > 0)
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
        log::trace(log_cat, "Exiting flush_streams()");
    }

    void Connection::schedule_packet_retransmit(std::chrono::steady_clock::time_point ts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        ngtcp2_tstamp exp_ns = ngtcp2_conn_get_expiry(conn.get());

        if (exp_ns == std::numeric_limits<ngtcp2_tstamp>::max())
        {
            log::info(log_cat, "No retransmit needed right now");
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
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::info(log_cat, "New stream ID:{}", id);

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
        stream._is_reading = stream._is_writing = false;

        if (stream._is_watermarked)
            stream.clear_watermarks();

        if (!was_closing)
        {
            log::trace(log_cat, "Invoking stream close callback");
            stream.closed(app_code);
        }
    }

    void Connection::stream_stop_sending(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        auto it = _streams.find(id);

        if (it == _streams.end())
            return;

        auto& stream = it->second;

        if (stream->_remote_reset.has_stop_sending_hook())
        {
            log::info(log_cat, "Invoking on_remote_stop_sending hook...");
            stream->_in_reset = true;
            stream->_remote_reset.on_remote_stop_sending(*stream.get(), app_code);
            stream->_in_reset = false;
        }
        else
        {
            log::info(log_cat, "No user-provided on_remote_stop_sending hook", app_code);
        }
    }

    void Connection::stream_reset(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        auto it = _streams.find(id);

        if (it == _streams.end())
            return;

        auto& stream = it->second;

        if (stream->_remote_reset.has_stream_reset_hook())
        {
            log::info(log_cat, "Invoking on_remote_stream_reset hook...");
            stream->_in_reset = true;
            stream->_remote_reset.on_remote_stream_reset(*stream.get(), app_code);
            stream->_in_reset = false;
        }
        else
        {
            log::info(log_cat, "No user-provided on_remote_stream_reset hook", app_code);
        }
    }

    void Connection::stream_closed(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        log::info(log_cat, "Stream {} closed with code {}", id, app_code);
        auto it = _streams.find(id);

        if (it == _streams.end())
            return;

        auto& stream = *it->second;
        stream_execute_close(stream, app_code);

        log::info(log_cat, "Erasing stream {}", id);
        _streams.erase(it);

        if (!ngtcp2_conn_is_local_stream(conn.get(), id))
            ngtcp2_conn_extend_max_streams_bidi(conn.get(), 1);

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
        assert(pseudo_stream);  // If this isn't set it means we've been in here before, but that
                                // shouldn't happen.
        pseudo_stream->_conn = nullptr;
        pseudo_stream.reset();
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

    int Connection::stream_receive(int64_t id, bstring_view data, bool fin)
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
            size_t sz = 0;

            if (str->_paused)
                str->_paused_offset += data.size();
            else
                sz = data.size();

            ngtcp2_conn_extend_max_offset(conn.get(), data.size());
            ngtcp2_conn_extend_max_stream_offset(conn.get(), id, sz);
        }

        return 0;
    }

    // this callback is defined for debugging datagrams
    int Connection::ack_datagram(uint64_t dgram_id)
    {
        log::trace(log_cat, "Connection (CID: {}) acked datagram ID:{}", _source_cid, dgram_id);
        return 0;
    }

    int Connection::recv_datagram(bstring_view data, bool fin)
    {
        log::trace(log_cat, "Connection (CID: {}) received datagram: {}", _source_cid, buffer_printer{data});

        std::optional<bstring> maybe_data;

        if (_packet_splitting)
        {
            if (data.size() < 2)
            {
                log::warning(log_cat, "Ignoring invalid datagram: too short for packet splitting");
                return 0;
            }

            uint16_t dgid = oxenc::load_big_to_host<uint16_t>(data.data());
            data.remove_prefix(2);

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
            log::debug(log_cat, "Connection (CID: {}) has no endpoint-supplied datagram data callback", _source_cid);
        else
        {
            bool good = false;

            try
            {
                datagrams->dgram_data_cb(*di, (maybe_data ? std::move(*maybe_data) : bstring{data.begin(), data.end()}));
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
            log::info(log_cat, "Connection (CID: {}) received fin from remote", _source_cid);
            // TODO: no clean up, as close cb is called after? Or just for streams
        }

        return 0;
    }

    ustring_view Connection::selected_alpn() const
    {
        return _endpoint.call_get([this]() { return get_session()->selected_alpn(); });
    }

    void Connection::send_datagram(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!_datagrams_enabled)
            throw std::runtime_error{"Endpoint not configured for datagram IO"};

        datagrams->send(data, std::move(keep_alive));
    }

    uint64_t Connection::get_streams_available_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return ngtcp2_conn_get_streams_bidi_left(conn.get());
    }

    size_t Connection::get_max_datagram_size_impl()
    {
        if (!_datagrams_enabled)
            return 0;

        // If packet splitting, we can take in double the datagram size
        size_t multiple = (_packet_splitting) ? 2 : 1;
        // Minus packet splitting overhead that adds 2 bytes of overhead per full or half datagram:
        size_t adjustment = DATAGRAM_OVERHEAD + (_packet_splitting ? 2 : 0);

        size_t max_dgram_size = multiple * (ngtcp2_conn_get_path_max_tx_udp_payload_size(conn.get()) - adjustment);
        if (max_dgram_size != _last_max_dgram_size)
        {
            _max_dgram_size_changed = true;
            _last_max_dgram_size = max_dgram_size;
        }

        return max_dgram_size;
    }

    std::optional<size_t> Connection::max_datagram_size_changed()
    {
        if (!_max_dgram_size_changed)
            return std::nullopt;
        return _endpoint.call_get([this]() -> std::optional<size_t> {
            // Check it again via an exchange, in case someone raced us here
            if (_max_dgram_size_changed.exchange(false))
                return _last_max_dgram_size;
            return std::nullopt;
        });
    }

    int Connection::init(
            ngtcp2_settings& settings,
            ngtcp2_transport_params& params,
            ngtcp2_callbacks& callbacks,
            std::chrono::nanoseconds handshake_timeout)
    {
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.path_validation = Callbacks::on_path_validation;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = Callbacks::on_recv_stream_data;
        callbacks.acked_stream_data_offset = Callbacks::on_acked_stream_data_offset;
        callbacks.stream_close = Callbacks::on_stream_close;
        callbacks.extend_max_local_streams_bidi = Callbacks::extend_max_local_streams_bidi;
        callbacks.rand = Callbacks::rand_cb;
        callbacks.get_new_connection_id = Callbacks::get_new_connection_id;
        callbacks.remove_connection_id = Callbacks::remove_connection_id;
        callbacks.dcid_status = Callbacks::on_connection_id_status;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.stream_reset = Callbacks::on_stream_reset;
        callbacks.stream_stop_sending = Callbacks::on_stream_stop_sending;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.stream_open = Callbacks::on_stream_open;
        callbacks.handshake_completed = Callbacks::on_handshake_completed;

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

        if (_datagrams_enabled)
        {
            log::trace(log_cat, "Enabling datagram support for connection");
            // This is effectively an "unlimited" value, which lets us accept any size that fits into a QUIC packet
            // (see rfc 9221)
            params.max_datagram_frame_size = 65535;
            // default ngtcp2 values set by ngtcp2_settings_default_versioned
            params.max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;  // 65527
            settings.max_tx_udp_payload_size = MAX_PMTUD_UDP_PAYLOAD;                // 1500 - 48 (approximate overhead)
            // settings.no_tx_udp_payload_size_shaping = 1;
            callbacks.recv_datagram = Callbacks::on_recv_datagram;
#ifndef NDEBUG
            callbacks.ack_datagram = Callbacks::on_ack_datagram;
#endif

            di = _endpoint.make_shared<dgram_interface>(*this);
        }
        else
        {
            // setting this value to 0 disables datagram support
            params.max_datagram_frame_size = 0;
            callbacks.recv_datagram = nullptr;
        }

        return 0;
    }

    Connection::Connection(
            Endpoint& ep,
            ConnectionID rid,
            const quic_cid& scid,
            const quic_cid& dcid,
            const Path& path,
            std::shared_ptr<IOContext> ctx,
            const std::vector<ustring>& alpns,
            std::chrono::nanoseconds default_handshake_timeout,
            std::optional<ustring> remote_pk,
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
            _datagrams_enabled{context->config.datagram_support},
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

        datagrams = _endpoint.make_shared<DatagramIO>(
                *this, _endpoint, context->dgram_data_cb ? context->dgram_data_cb : ep.dgram_recv_cb);
        pseudo_stream = _endpoint.make_shared<Stream>(*this, _endpoint);
        pseudo_stream->_stream_id = -1;

        const auto d_str = is_outbound() ? "outbound"s : "inbound"s;
        log::trace(log_cat, "Creating new {} connection object", d_str);

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;
        int rv = 0;

        auto handshake_timeout = context->config.handshake_timeout.value_or(default_handshake_timeout);
        if (rv = init(settings, params, callbacks, handshake_timeout); rv != 0)
            log::critical(log_cat, "Error: {} connection not created", d_str);

        tls_session = tls_creds->make_session(*this, alpns);

        if (is_outbound())
        {
            callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
            callbacks.handshake_confirmed = Callbacks::on_handshake_confirmed;
            callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
            callbacks.recv_new_token = Callbacks::on_recv_token;

            // Clients should be the ones providing a remote pubkey here. This way we can emplace it into
            // the gnutlssession object to be verified. Servers should be verifying via callback
            assert(remote_pk.has_value());
            remote_pubkey = *remote_pk;
            tls_session->set_expected_remote_key(remote_pubkey);

            if (auto maybe_token = _endpoint.get_path_validation_token(remote_pubkey))
            {
                settings.token = maybe_token->data();
                settings.tokenlen = maybe_token->size();
            }

            // TODO: uncomment this with 0RTT resumption
            // if (auto maybe_params = _endpoint.get_0rtt_transport_params(remote_pubkey))
            // {
            //     if (auto rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
            //                 conn.get(), maybe_params->data(), maybe_params->size());
            //         rv != 0)
            //         log::warning(log_cat, "Client failed to decode and set 0rtt transport params!");
            //     else
            //         log::info(log_cat, "Client decoded and set 0rtt transport params!");
            // }

            rv = ngtcp2_conn_client_new(
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
            callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

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
            // params.stateless_reset_token_present = 1;
            settings.token = hdr->token;
            settings.tokenlen = hdr->tokenlen;

            // gnutls_rnd(GNUTLS_RND_RANDOM, params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN);

            if (token_type)
                settings.token_type = *token_type;

            rv = ngtcp2_conn_server_new(
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

        if (rv != 0)
        {
            log::critical(log_cat, "Error: failed to initialize {} ngtcp2 connection: {}", d_str, ngtcp2_strerror(rv));
            throw std::runtime_error{"Failed to initialize connection object: "s + ngtcp2_strerror(rv)};
        }

        ngtcp2_conn_set_keep_alive_timeout(connptr, std::chrono::nanoseconds{context->config.keep_alive}.count());

        tls_session->conn_ref.get_conn = get_conn;
        tls_session->conn_ref.user_data = this;
        ngtcp2_conn_set_tls_native_handle(connptr, tls_session->get_session());

        conn.reset(connptr);

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
            const std::vector<ustring>& alpns,
            std::chrono::nanoseconds default_handshake_timeout,
            std::optional<ustring> remote_pk,
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
        return endpoint().call_get([this]() -> int { return get_max_datagram_size_impl(); });
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
