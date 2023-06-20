#include "connection.hpp"

#include <arpa/inet.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <netinet/ip.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <uvw/async.h>
#include <uvw/timer.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <stdexcept>

#include "client.hpp"
#include "endpoint.hpp"
#include "handler.hpp"
#include "server.hpp"
#include "stream.hpp"

namespace oxen::quic
{
    using namespace std::literals;

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(conn_ref->user_data)->conn.get();
        }

        void log_printer(void* user_data, const char* fmt, ...)
        {
            std::array<char, 2048> buf{};
            va_list ap;
            va_start(ap, fmt);
            if (vsnprintf(buf.data(), buf.size(), fmt, ap) >= 0)
                log::debug(log_cat, "{}", buf.data());
            va_end(ap);
        }
    }

    auto get_time()
    {
        return std::chrono::steady_clock::now();
    }

    int hook_func(
            gnutls_session_t session, unsigned int htype, unsigned when, unsigned int incoming, const gnutls_datum_t* msg)
    {
        (void)session;
        (void)htype;
        (void)when;
        (void)incoming;
        (void)msg;
        /* we could save session data here */

        return 0;
    }

    int recv_stream_data(
            ngtcp2_conn* conn,
            uint32_t flags,
            int64_t stream_id,
            uint64_t offset,
            const uint8_t* data,
            size_t datalen,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_receive(
                stream_id, {reinterpret_cast<const std::byte*>(data), datalen}, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    }

    int acked_stream_data_offset(
            ngtcp2_conn* conn_,
            int64_t stream_id,
            uint64_t offset,
            uint64_t datalen,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::info(log_cat, "Ack [{},{}]", offset, offset + datalen);
        return static_cast<Connection*>(user_data)->stream_ack(stream_id, datalen);
    }

    int on_stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_opened(stream_id);
    }

    int on_stream_close(
            ngtcp2_conn* conn,
            uint32_t flags,
            int64_t stream_id,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    int on_stream_reset(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t final_size,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx)
    {
        (void)rand_ctx;
        (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
    }

    int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        (void)conn;
        (void)user_data;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        cid->datalen = cidlen;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        return 0;
    }

    int recv_rx_key(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data)
    {
        // fix this
        return 0;
    }

    int recv_tx_key(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data)
    {
        // same
        return 0;
    }

    int extend_max_local_streams_bidi(ngtcp2_conn* _conn, uint64_t max_streams, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        auto& conn = *static_cast<Connection*>(user_data);
        assert(_conn == conn);

        if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn); remaining > 0)
            conn.check_pending_streams(remaining);

        return 0;
    }

    Server* Connection::server()
    {
        return dynamic_cast<Server*>(&endpoint);
    }
    const Server* Connection::server() const
    {
        return dynamic_cast<const Server*>(&endpoint);
    }

    Client* Connection::client()
    {
        return dynamic_cast<Client*>(&endpoint);
    }
    const Client* Connection::client() const
    {
        return dynamic_cast<const Client*>(&endpoint);
    }

    void Connection::io_ready()
    {
        io_trigger->send();
    }

    // note: this does not need to return anything, it is never called except in on_stream_available
    // First, we check the list of pending streams on deck to see if they're ready for broadcast. If
    // so, we move them to the streams map, where they will get picked up by flush_streams and dump
    // their buffers. If none are ready, we keep chugging along and make another stream as usual. Though
    // if none of the pending streams are ready, the new stream really shouldn't be ready, but here we are
    void Connection::check_pending_streams(int available, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        int popped = 0;

        while (!pending_streams.empty() && popped < available)
        {
            auto& str = pending_streams.front();

            if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &str->stream_id, str.get()); rv == 0)
            {
                log::debug(log_cat, "Stream [ID:{}] ready for broadcast, moving out of pending streams", str->stream_id);
                str->set_ready();
                popped += 1;
                streams[str->stream_id] = std::move(str);
                pending_streams.pop_front();
            }
            else
                return;
        }
    }

    std::shared_ptr<Stream> Connection::get_new_stream(stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        auto stream = std::make_shared<Stream>(*this, std::move(data_cb), std::move(close_cb));

        if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &stream->stream_id, stream.get()); rv != 0)
        {
            log::warning(log_cat, "Stream not ready [Code: {}]; adding to pending streams list", ngtcp2_strerror(rv));
            stream->set_not_ready();
            pending_streams.push_back(std::move(stream));
            return pending_streams.back();
        }
        else
        {
            log::debug(log_cat, "Stream {} successfully created; ready to broadcast", stream->stream_id);
            stream->set_ready();
            auto& strm = streams[stream->stream_id];
            strm = std::move(stream);
            return strm;
        }
    }

    void Connection::on_io_ready()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        flush_streams();
        schedule_retransmit();
    }

    io_result Connection::send()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(send_buffer_size <= send_buffer.size());
        io_result rv{};
        bstring_view send_data{send_buffer.data(), send_buffer_size};

        log::trace(log_cat, "Sending to {}: {}", path.remote.to_string(), buffer_printer{send_data});

        if (!send_data.empty())
            rv = endpoint.send_packet(path, send_data);

        return rv;
    }

    void Connection::flush_streams()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        // Maximum number of stream data packets to send out at once; if we reach this then we'll
        // schedule another event loop call of ourselves (so that we don't starve the loop)
        auto max_udp_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(conn.get());
        auto max_stream_packets = ngtcp2_conn_get_send_quantum(conn.get()) / max_udp_payload_size;
        ngtcp2_ssize ndatalen;
        uint16_t stream_packets = 0;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        uint64_t ts = get_timestamp();
        pkt_info = {};

        auto send_packet = [&](auto nwrite) -> int {
            send_buffer_size = nwrite;

            auto sent = send();
            if (sent.blocked())
            {
                log::warning(log_cat, "Error: Packet send blocked, scheduling retransmit");
                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                schedule_retransmit();
                return 0;
            }

            send_buffer_size = 0;

            if (!sent)
            {
                log::warning(log_cat, "Error: I/O error while trying to send packet");
                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                return 0;
            }
            log::trace(log_cat, "Packet away!");
            return 1;
        };

        std::list<Stream*> strs;
        for (auto& [stream_id, stream_ptr] : streams)
        {
            if (stream_ptr and not stream_ptr->sent_fin)
            {
                try
                {
                    strs.push_back(stream_ptr.get());
                }
                catch (std::exception& e)
                {
                    log::error(log_cat, "Exception caught: {}", e.what());
                }
            }
        }

        while (!strs.empty() && stream_packets < max_stream_packets)
        {
            for (auto it = strs.begin(); it != strs.end();)
            {
                log::trace(
                        log_cat, "Max stream packets: {}\nCurrent stream packets: {}", max_stream_packets, stream_packets);

                auto& stream = **it;
                auto bufs = stream.pending();

                if (stream.is_closing && !stream.sent_fin && stream.unsent() == 0)
                {
                    log::trace(log_cat, "Sending FIN");
                    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    stream.sent_fin = true;
                }
                else if (bufs.empty())
                {
                    log::debug(log_cat, "pending() returned empty buffer for stream ID {}, moving on", stream.stream_id);
                    it = strs.erase(it);
                    continue;
                }

                /*
                in "for each stream" loop, keep track of whether or not we're in the middle of a
                packet, i.e. when we call write_v stream we are starting (or continuing) a packet,
                and if we call send_packet we finished one.

                then in the next loop (for(;;)), call writev_stream differently based on that, and
                if we send_packet there we're also no longer in the middle of a packet
                */

                auto nwrite = ngtcp2_conn_writev_stream(
                        conn.get(),
                        &path.path,
                        &pkt_info,
                        u8data(send_buffer),
                        send_buffer.size(),
                        &ndatalen,
                        flags,
                        stream.stream_id,
                        bufs.data(),
                        bufs.size(),
                        (!ts) ? get_timestamp() : ts);

                log::debug(log_cat, "add_stream_data for stream {} returned [{},{}]", stream.stream_id, nwrite, ndatalen);

                if (nwrite < 0)
                {
                    if (nwrite == -240)  // NGTCP2_ERR_WRITE_MORE
                    {
                        log::debug(
                                log_cat, "Consumed {} bytes from stream {} and have space left", ndatalen, stream.stream_id);
                        assert(ndatalen >= 0);
                        stream.wrote(ndatalen);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                    {
                        log::info(log_cat, "Cannot write to {}: stream is closing", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR)  // -230
                    {
                        log::info(log_cat, "Cannot add to stream {}: stream is shut, proceeding", stream.stream_id);
                        assert(ndatalen == -1);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                    {
                        log::info(log_cat, "Cannot add to stream {}: stream is blocked", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }

                    log::error(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                    break;
                }

                if (ndatalen >= 0)
                {
                    log::debug(log_cat, "consumed {} bytes from stream {}", ndatalen, stream.stream_id);
                    stream.wrote(ndatalen);
                }

                if (nwrite == 0)  //  we are congested
                {
                    log::info(log_cat, "Done stream writing to {} (stream is congested)", stream.stream_id);

                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    //  we are congested, so clear pending streams to exit outer loop
                    //  and enter next loop to flush unsent stuff
                    strs.clear();
                    break;
                }

                log::info(log_cat, "Sending stream data packet");
                if (!send_packet(nwrite))
                    return;

                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                if (stream.unsent() == 0)
                    it = strs.erase(it);
                else
                    ++it;

                if (++stream_packets == max_stream_packets)
                {
                    log::info(log_cat, "Max stream packets ({}) reached", max_stream_packets);
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    return;
                }
            }
        }

        // Now try more with stream id -1 and no data: this takes care of things like initial
        // handshake packets, and also finishes off any partially-filled packet from above.
        for (;;)
        {
            log::info(log_cat, "Calling add_stream_data for empty stream");

            auto nwrite = ngtcp2_conn_writev_stream(
                    conn.get(),
                    &path.path,
                    &pkt_info,
                    u8data(send_buffer),
                    send_buffer.size(),
                    &ndatalen,
                    flags,
                    -1,
                    nullptr,
                    0,
                    (!ts) ? get_timestamp() : ts);

            log::info(log_cat, "add_stream_data for non-stream returned [{},{}]", nwrite, ndatalen);
            assert(ndatalen <= 0);

            if (nwrite == 0)
            {
                log::info(log_cat, "Nothing else to write for non-stream data for now (or we are congested)");
                break;
            }

            if (nwrite < 0)
            {
                if (nwrite == NGTCP2_ERR_WRITE_MORE)  // -240
                {
                    log::info(log_cat, "Writing non-stream data frames, and have space left");
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                {
                    log::warning(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                    break;
                }
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                {
                    log::info(log_cat, "Cannot add to empty stream right now: stream is blocked");
                    break;
                }

                log::warning(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                break;
            }

            log::info(log_cat, "Sending data packet with non-stream data frames");
            if (auto rv = send_packet(nwrite); rv != 0)
                return;
            ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
        }

        log::info(log_cat, "Exiting flush_streams()");
    }

    void Connection::schedule_retransmit()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto exp = ngtcp2_conn_get_expiry(conn.get());
        auto expiry = std::chrono::nanoseconds{static_cast<std::chrono::nanoseconds::rep>(exp)};
        auto ngtcp2_expiry_delta =
                std::chrono::duration_cast<std::chrono::milliseconds>(expiry - get_time().time_since_epoch());

        if (exp == std::numeric_limits<decltype(exp)>::max())
        {
            log::info(log_cat, "No retransmit needed, expiration passed");
            retransmit_timer->stop();
            return;
        }

        log::info(log_cat, "Expiry delta: {}", ngtcp2_expiry_delta.count());

        auto expires_in = std::max(0ms, ngtcp2_expiry_delta);
        retransmit_timer->stop();
        retransmit_timer->start(expires_in, 0ms);
    }

    const std::shared_ptr<Stream>& Connection::get_stream(int64_t ID) const
    {
        return streams.at(ID);
    }

    int Connection::stream_opened(int64_t id)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::info(log_cat, "New stream ID:{}", id);

        auto stream = std::make_shared<Stream>(*this, id);

        stream->stream_id = id;
        uint64_t rv{0};

        auto srv = stream->conn.server();

        if (srv)
        {
            stream->data_callback = srv->context->stream_data_cb;

            if (srv->context->stream_open_cb)
                rv = srv->context->stream_open_cb(*stream);
        }

        if (rv != 0)
        {
            log::info(log_cat, "stream_open_callback returned failure, dropping stream {}", id);
            ngtcp2_conn_shutdown_stream(conn.get(), 0, id, 1);
            io_ready();
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        auto [it, ins] = streams.emplace(id, std::move(stream));
        assert(ins);
        log::info(log_cat, "Created new incoming stream {}", id);
        return 0;
    }

    void Connection::stream_closed(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        log::info(log_cat, "Stream {} closed with code {}", id, app_code);
        auto it = streams.find(id);

        if (it == streams.end())
            return;

        auto& stream = *it->second;
        const bool was_closing = stream.is_closing;
        stream.is_closing = stream.is_shutdown = true;

        if (!was_closing && stream.close_callback)
        {
            log::trace(log_cat, "Invoking stream close callback");
            std::optional<uint64_t> code;
            if (app_code != 0)
                code = app_code;
            stream.close_callback(stream, *code);
        }

        log::info(log_cat, "Erasing stream {}", id);
        streams.erase(it);

        if (!ngtcp2_conn_is_local_stream(conn.get(), id))
            ngtcp2_conn_extend_max_streams_bidi(conn.get(), 1);

        io_ready();
    }

    int Connection::stream_ack(int64_t id, size_t size)
    {
        if (auto it = streams.find(id); it != streams.end())
        {
            it->second->acknowledge(size);
            return 0;
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int Connection::stream_receive(int64_t id, bstring_view data, bool fin)
    {
        log::trace(log_cat, "Stream (ID: {}) received data: {}", id, buffer_printer{data});
        auto str = get_stream(id);

        if (!str->data_callback)
            log::debug(log_cat, "Stream (ID: {}) has no user-supplied data callback", str->stream_id);
        else
        {
            bool good = false;

            try
            {
                str->data_callback(*str, data);
                good = true;
            }
            catch (const std::exception& e)
            {
                log::warning(
                        log_cat,
                        "Stream {} data callback raised exception ({}); closing stream with app "
                        "code "
                        "{}",
                        str->stream_id,
                        e.what(),
                        STREAM_ERROR_EXCEPTION);
            }
            catch (...)
            {
                log::warning(
                        log_cat,
                        "Stream {} data callback raised an unknown exception; closing stream with "
                        "app "
                        "code {}",
                        str->stream_id,
                        STREAM_ERROR_EXCEPTION);
            }
            if (!good)
            {
                str->close(STREAM_ERROR_EXCEPTION);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }

        if (fin)
        {
            log::info(log_cat, "Stream {} closed by remote", str->stream_id);
            // no clean up, close_cb called after this
        }
        else
        {
            ngtcp2_conn_extend_max_stream_offset(conn.get(), id, data.size());
            ngtcp2_conn_extend_max_offset(conn.get(), data.size());
        }

        return 0;
    }

    int Connection::get_streams_available()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint64_t open = ngtcp2_conn_get_streams_bidi_left(conn.get());
        if (open > std::numeric_limits<uint64_t>::max())
            return -1;
        return static_cast<int>(open);
    }

    int Connection::init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks)
    {
        auto loop = quic_manager->loop();
        io_trigger = loop->resource<uvw::async_handle>();
        io_trigger->on<uvw::async_event>([this](auto&, auto&) { on_io_ready(); });

        retransmit_timer = loop->resource<uvw::timer_handle>();
        retransmit_timer->on<uvw::timer_event>([this](auto&, auto&) {
            log::info(log_cat, "Retransmit timer fired!");
            if (auto rv = ngtcp2_conn_handle_expiry(conn.get(), get_timestamp()); rv != 0)
            {
                log::warning(log_cat, "Error: expiry handler invocation returned error code: %s", ngtcp2_strerror(rv));
                endpoint.close_connection(*this, rv);
            }
            else
            {
                on_io_ready();
            }
        });

        retransmit_timer->start(0ms, 0ms);

        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = recv_stream_data;
        callbacks.acked_stream_data_offset = acked_stream_data_offset;
        callbacks.stream_close = on_stream_close;
        callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
        callbacks.rand = rand_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.stream_reset = on_stream_reset;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        // callbacks.recv_rx_key = recv_rx_key;
        // callbacks.recv_tx_key = recv_tx_key;
        // callbacks.dcid_status = NULL;
        // callbacks.handshake_completed = NULL;
        // callbacks.handshake_confirmed = NULL;

        ngtcp2_settings_default(&settings);

        settings.initial_ts = get_timestamp();
        settings.log_printf = log_printer;
        settings.max_tx_udp_payload_size = 1200;
        settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;

        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 1024 * 1024;
        // Max concurrent streams supported on one connection
        params.initial_max_streams_uni = 0;
        params.initial_max_streams_bidi = 32;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to
        // us)
        params.initial_max_stream_data_bidi_local = 64 * 1024;
        params.initial_max_stream_data_bidi_remote = 64 * 1024;
        params.max_idle_timeout = std::chrono::nanoseconds(5min).count();
        params.active_connection_id_limit = 8;

        return 0;
    }

    // client conn
    Connection::Connection(
            Client& client,
            std::shared_ptr<Handler> ep,
            const ConnectionID& scid,
            const Path& path,
            std::shared_ptr<uvw::udp_handle> handle) :
            endpoint{client},
            quic_manager{ep},
            source_cid{scid},
            dest_cid{ConnectionID::random()},
            path{path},
            local{client.context->local},
            remote{client.context->remote},
            udp_handle{handle},
            tls_context{client.context->tls_ctx}
    {
        log::trace(log_cat, "Creating new client connection object");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;

        if (auto rv = init(settings, params, callbacks); rv != 0)
            log::warning(log_cat, "Error: Client-based connection not created");

        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

        int rv = ngtcp2_conn_client_new(
                &connptr, &dest_cid, &source_cid, path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

        // set conn_ref fxn to return ngtcp2_crypto_conn_ref
        tls_context->conn_ref.get_conn = get_conn;
        // store pointer to connection in user_data
        tls_context->conn_ref.user_data = this;

        ngtcp2_conn_set_tls_native_handle(connptr, tls_context->session);
        conn.reset(connptr);

        if (rv != 0)
        {
            throw std::runtime_error{"Failed to initialize client connection to server: "s + ngtcp2_strerror(rv)};
        }

        log::info(log_cat, "Successfully created new client connection object");
    }

    // server conn
    Connection::Connection(
            Server& server,
            std::shared_ptr<Handler> ep,
            const ConnectionID& cid,
            ngtcp2_pkt_hd& hdr,
            const Path& path,
            std::shared_ptr<TLSContext> ctx) :
            endpoint{server},
            quic_manager{ep},
            source_cid{cid},
            dest_cid{hdr.scid},
            path{path},
            local{server.context->local},
            remote{path.remote},
            tls_context{ctx}
    {
        log::trace(log_cat, "Creating new server connection object");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;

        if (auto rv = init(settings, params, callbacks); rv != 0)
            log::warning(log_cat, "Error: Server-based connection not created");

        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.stream_open = on_stream_open;

        params.original_dcid = hdr.dcid;
        params.original_dcid_present = 1;

        settings.token = hdr.token;

        int rv = ngtcp2_conn_server_new(
                &connptr, &dest_cid, &source_cid, path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

        // set conn_ref fxn to return ngtcp2_crypto_conn_ref
        tls_context->conn_ref.get_conn = get_conn;
        // store pointer to connection in user_data
        tls_context->conn_ref.user_data = this;

        ngtcp2_conn_set_tls_native_handle(connptr, tls_context->session);
        conn.reset(connptr);

        if (rv != 0)
        {
            throw std::runtime_error{"Failed to initialize server connection to client: "s + ngtcp2_strerror(rv)};
        }

        log::info(log_cat, "Successfully created new server connection object");
    }

    Connection::~Connection()
    {
        if (io_trigger)
            io_trigger->close();
        if (retransmit_timer)
        {
            retransmit_timer->stop();
            retransmit_timer->close();
        }
    }

}  // namespace oxen::quic
