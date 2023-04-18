#include "connection.hpp"
#include "server.hpp"
#include "client.hpp"
#include "tunnel.hpp"
#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw/async.h>
#include <uvw/timer.h>

#include <memory>
#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <netinet/ip.h>
#include <stdexcept>


namespace oxen::quic
{
    using namespace std::literals;

    int 
    hook_func(gnutls_session_t session, unsigned int htype, unsigned when, 
            unsigned int incoming, const gnutls_datum_t *msg) 
    {
		(void)session;
		(void)htype;
		(void)when;
		(void)incoming;
		(void)msg;
		/* we could save session data here */

		return 0;
	}

    int 
    numeric_host_family(const char *hostname, int family) 
    {
		uint8_t dst[sizeof(struct in6_addr)];
		return inet_pton(family, hostname, dst) == 1;
	}

	int 
    numeric_host(const char *hostname) 
    {
		return numeric_host_family(hostname, AF_INET) ||
			numeric_host_family(hostname, AF_INET6);
    }

    extern "C" inline void 
    log_printer(void *user_data, const char *fmt, ...) 
    {
        fprintf(stderr, "ding\n");
        va_list ap;
        va_start(ap, fmt);
        
        //if (vsnprintf(buf.data(), buf.size(), fmt, ap) >= 0)
        vfprintf(stderr, fmt, ap);
        va_end(ap);

        fprintf(stderr, "\n");
    }

    int
    recv_stream_data(
        ngtcp2_conn* conn,
        uint32_t flags,
        int64_t stream_id,
        uint64_t offset,
        const uint8_t* data,
        size_t datalen,
        void* user_data,
        void* stream_user_data)
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_receive(
            stream_id,
            {reinterpret_cast<const std::byte*>(data), datalen},
            flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    }

    int
    acked_stream_data_offset(
        ngtcp2_conn* conn_,
        int64_t stream_id,
        uint64_t offset,
        uint64_t datalen,
        void* user_data,
        void* stream_user_data)
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        fprintf(stderr, "Ack [%lu,%lu)\n", offset, offset + datalen);
        return static_cast<Connection*>(user_data)->stream_ack(stream_id, datalen);
    }

    int
    stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data)
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_opened(stream_id);
    }

    int
    stream_close_cb(
        ngtcp2_conn* conn,
        uint32_t flags,
        int64_t stream_id,
        uint64_t app_error_code,
        void* user_data,
        void* stream_user_data)
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    int
    stream_reset_cb(
        ngtcp2_conn* conn,
        int64_t stream_id,
        uint64_t final_size,
        uint64_t app_error_code,
        void* user_data,
        void* stream_user_data)
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    void 
    rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) 
    {
        (void)rand_ctx;

        (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
    }

    int 
    get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, 
                            size_t cidlen, void *user_data) 
    {
        (void)conn;
        (void)user_data;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        cid->datalen = cidlen;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        return 0;
    }

    int 
    extend_max_local_streams_bidi(ngtcp2_conn* _conn, uint64_t max_streams, void* user_data) 
    {
    #ifdef MESSAGE
        auto& conn = *static_cast<Connection*>(user_data);
        assert(_conn == conn);

        if (conn.on_stream_available)
        {
            if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn); remaining > 0)
                conn.on_stream_available(conn);
        }
    #else
        (void)_conn;
        (void)max_streams;
        (void)user_data;
    #endif
        return 0;
    }

    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref *conn_ref) 
    {
        Connection *c = reinterpret_cast<Connection*>(conn_ref->user_data);
        return c->conn.get();
    }


    void
    Connection::io_ready()
    {
        io_trigger->send();
    }


    const std::shared_ptr<Stream>&
    Connection::open_stream(data_callback_t data_cb, close_callback_t close_cb)
    {
        std::shared_ptr<Stream> stream{new Stream{
            *this, std::move(data_cb), std::move(close_cb), endpoint->default_stream_bufsize}};
        if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &stream->stream_id, stream.get());
            rv != 0)
            throw std::runtime_error{"Stream creation failed: "s + ngtcp2_strerror(rv)};

        auto& strm = streams[stream->stream_id];
        strm = std::move(stream);

        return strm;
    }


    void
    Connection::on_io_ready()
    {
        fprintf(stderr, "%s called\n", __PRETTY_FUNCTION__);
        flush_streams();
        schedule_retransmit();
        fprintf(stderr, "%s finished\n", __PRETTY_FUNCTION__);
    }


    io_result
    Connection::send()
    {
        assert(send_buffer_size <= send_buffer.size());
        io_result rv{};
        bstring send_data{send_buffer.data(), send_buffer_size};

        if (!send_data.empty())
            rv = tun_endpoint.send_packet(path.remote, send_data, pkt_info.ecn, pkt_type);

        return rv;
    }


    void
    Connection::flush_streams()
    {
        fprintf(stderr, "Calling Connection::flush_streams()\n");
        // Maximum number of stream data packets to send out at once; if we reach this then we'll
        // schedule another event loop call of ourselves (so that we don't starve the loop).
        auto max_udp_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(conn.get());
        auto max_stream_packets = ngtcp2_conn_get_send_quantum(conn.get()) / max_udp_payload_size;
        ngtcp2_ssize ndatalen;
        uint16_t stream_packets = 0;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        uint64_t ts = get_timestamp();
        pkt_info = {};

        auto send_packet = [&](auto nwrite) -> int 
        {
            send_buffer_size = nwrite;

            auto sent = send();
            if (sent.blocked())
            {
                fprintf(stderr, "Error: Packet send blocked, scheduling retransmit\n");
                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                schedule_retransmit();
                return 0;
            }

            send_buffer_size = 0;
            if (!sent)
            {
                fprintf(stderr, "Error: I/O error while trying to send packet\n");
                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                return 0;
            }
            fprintf(stderr, "Packet away!\n");
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
                    fprintf(stderr, "Exception caught: %s\n", e.what());
                }
            }
            }

        while (!strs.empty() && stream_packets < max_stream_packets)
        {
            for (auto it = strs.begin(); it != strs.end();)
            {
                fprintf(
                    stderr,
                    "Max stream packets: %lu\nCurrent stream packets: %hu\n",
                    max_stream_packets,
                    stream_packets);

                auto& stream = **it;
                auto bufs = stream.pending();

                std::vector<ngtcp2_vec> vecs;
                vecs.reserve(bufs.size());
                std::transform(bufs.begin(), bufs.end(), std::back_inserter(vecs), [](const auto& buf) {
                    return ngtcp2_vec{const_cast<uint8_t*>(u8data(buf)), buf.size()};
                });

                if (stream.is_closing && !stream.sent_fin && stream.unsent() == 0)
                {
                    fprintf(stderr, "Sending FIN\n");
                    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    stream.sent_fin = true;
                }
                else if (stream.is_new)
                {
                    stream.is_new = false;
                }

                auto nwrite = ngtcp2_conn_writev_stream(
                    conn.get(),
                    &path.path,
                    &pkt_info,
                    u8data(send_buffer),
                    send_buffer.size(),
                    &ndatalen,
                    flags,
                    stream.stream_id,
                    reinterpret_cast<const ngtcp2_vec*>(vecs.data()),
                    vecs.size(),
                    (!ts) ? get_timestamp() : ts);

                fprintf(stderr, "add_stream_data for stream %lu  returned [{%lu},{%lu}]\n",
                    stream.stream_id, nwrite, ndatalen);

                if (nwrite < 0)
                {
                    if (nwrite == -240)  // NGTCP2_ERR_WRITE_MORE
                    {
                        fprintf(stderr, "Consumed %lu bytes from stream %lu and have space left\n",
                            ndatalen, stream.stream_id);
                        assert(ndatalen >= 0);
                        stream.wrote(ndatalen);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                    {
                        fprintf(stderr, "Cannot write to %lu: stream is closing\n", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR)  // -230
                    {
                        fprintf(stderr, "Cannot add to stream %lu: stream is shut, proceeding\n", stream.stream_id);
                        assert(ndatalen == -1);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                    {
                        fprintf(stderr, "Cannot add to stream %lu: stream is blocked\n", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }

                    fprintf(stderr, "Error writing non-stream data: %s\n", ngtcp2_strerror(nwrite));
                    break;
                }

                if (ndatalen >= 0)
                {
                    fprintf(stderr, "consumed %lu bytes from stream %lu\n", ndatalen, stream.stream_id);
                    stream.wrote(ndatalen);
                }

                if (nwrite == 0)  //  we are congested
                {
                    fprintf(stderr, "Done stream writing to %lu (stream is congested)\n", stream.stream_id);

                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    //  we are congested, so clear pending streams to exit outer loop
                    //  and enter next loop to flush unsent stuff
                    strs.clear();
                    break;
                }

                fprintf(stderr, "Sending stream data packet\n");
                if (!send_packet(nwrite))
                    return;

                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                if (stream.unsent() == 0)
                    it = strs.erase(it);
                else
                    ++it;

                if (++stream_packets == max_stream_packets)
                {
                    fprintf(stderr, "Max stream packets ({%lu) reached\n", max_stream_packets);
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    return;
                }
            }
        }

        // Now try more with stream id -1 and no data: this takes care of things like initial handshake
        // packets, and also finishes off any partially-filled packet from above.
        for (;;)
        {
            fprintf(stderr, "Calling add_stream_data for empty stream\n");

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

            fprintf(stderr, "add_stream_data for non-stream returned [{%lu},{%lu}]\n", nwrite, ndatalen);
            assert(ndatalen <= 0);

            if (nwrite == 0)
            {
                fprintf(
                    stderr, "Nothing else to write for non-stream data for now (or we are congested)\n");
                break;
            }

            if (nwrite < 0)
            {
                if (nwrite == NGTCP2_ERR_WRITE_MORE)  // -240
                {
                    fprintf(stderr, "Writing non-stream data frames, and have space left\n");
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                {
                    fprintf(stderr, "Error writing non-stream data: %s\n", ngtcp2_strerror(nwrite));
                    break;
                }
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                {
                    fprintf(stderr, "Cannot add to empty stream right now: stream is blocked\n");
                    break;
                }

                fprintf(stderr, "Error writing non-stream data: %s\n", ngtcp2_strerror(nwrite));
                break;
            }

            fprintf(stderr, "Sending data packet with non-stream data frames\n");
            if (auto rv = send_packet(nwrite); rv != 0)
                return;
            ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
        }

        fprintf(stderr, "Exiting flush_streams()\n");
    }


    Server*
    Connection::server()
    {
        return dynamic_cast<Server*>(endpoint.get());
    }

    Client*
    Connection::client()
    {
        return dynamic_cast<Client*>(endpoint.get());
    }


    void
    Connection::schedule_retransmit()
    {
        auto exp = static_cast<uvw::Loop::Time>(ngtcp2_conn_get_expiry(conn.get()));
        auto now = static_cast<uvw::Loop::Time>(get_timestamp());
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(exp - now);

        if (exp == std::numeric_limits<decltype(exp)>::max())
        {
            fprintf(stderr, "No retransmit needed, expiration passed\n");
            retransmit_timer->stop();
            return;
        }

        auto expiry = std::max(0ms, delta);
        retransmit_timer->stop();
        retransmit_timer->start(expiry, 0ms);
    }

    const std::shared_ptr<Stream>&
    Connection::get_stream(int64_t ID) const
    {
        return streams.at(ID);
    }


    int
    Connection::stream_opened(int64_t id)
    {
        fprintf(stderr, "New stream %lu\n", id);
        auto* serv = server();

        if (!serv)
        {
            fprintf(stderr, "We are a client, incoming streams are not accepted\n");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        std::shared_ptr<Stream> stream{new Stream{*this, id, endpoint->default_stream_bufsize}};
        
        stream->stream_id = id;
        bool good = true;
        if (serv->stream_open_callback)
            good = serv->stream_open_callback(*stream, client_tunnel_port);
        if (!good)
        {
            fprintf(stderr, "stream_open_callback returned failure, dropping stream %lu\n", id);
            ngtcp2_conn_shutdown_stream(conn.get(), id, 1);
            io_ready();
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        [[maybe_unused]] auto [it, ins] = streams.emplace(id, std::move(stream));
        assert(ins);
        fprintf(stderr, "Created new incoming stream %lu\n", id);
        return 0;
    }


    void
    Connection::stream_closed(int64_t id, uint64_t app_code)
    {
        assert(ngtcp2_is_bidi_stream(id));
        fprintf(stderr, "Stream %lu closed with code %lu\n", id, app_code);
        auto it = streams.find(id);

        if (it == streams.end())
            return;

        auto& stream = *it->second;
        const bool was_closing = stream.is_closing;
        stream.is_closing = stream.is_shutdown = true;
        if (!was_closing && stream.close_callback)
        {
            fprintf(stderr, "Invoke stream close callback\n");
            std::optional<uint64_t> code;
            if (app_code != 0)
                code = app_code;
            stream.close_callback(stream, *code);
        }

        fprintf(stderr, "Erasing stream %lu\n", id);
        streams.erase(it);

        if (!ngtcp2_conn_is_local_stream(conn.get(), id))
            ngtcp2_conn_extend_max_streams_bidi(conn.get(), 1);

        io_ready();
    }


    int
    Connection::stream_ack(int64_t id, size_t size)
    {
        if (auto it = streams.find(id); it != streams.end())
        {
            it->second->acknowledge(size);
            return 0;
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }


    int
    Connection::stream_receive(int64_t id, bstring data, bool fin)
    {
        auto str = get_stream(id);

        if (!str->data_callback)
            fprintf(stderr, "Dropping incoming data on stream %lu: stream has no data callback set\n", str->stream_id);
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
                fprintf(stderr, "Stream %lu data callback raised exception (%s); closing stream with app code %lu\n",
                    str->stream_id, e.what(), STREAM_ERROR_EXCEPTION);
            }
            catch (...)
            {
                fprintf(stderr, "Stream %lu data callback raised an unknown exception; closing stream with app code %lu\n",
                    str->stream_id, STREAM_ERROR_EXCEPTION);
            }
            if (!good)
            {
                str->close(STREAM_ERROR_EXCEPTION);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        if (fin)
        {
            fprintf(stderr, "Stream %lu closed by remote\n", str->stream_id);
            // no clean up, close_cb called after this
        }
        else
        {
            ngtcp2_conn_extend_max_stream_offset(conn.get(), id, data.size());
            ngtcp2_conn_extend_max_offset(conn.get(), data.size());
        }
        return 0;
    }


    int
    Connection::init_gnutls(Client& client)
    {
        fprintf(stderr, "Initializing client gnutls session\n");

        int rv = gnutls_certificate_allocate_credentials(&cred);

        if (rv == 0)
            rv = gnutls_certificate_set_x509_system_trust(cred);
        if (rv < 0) {
            fprintf(stderr, "cred init failed: %d: %s\n", rv, gnutls_strerror(rv));
            return -1;
        }

        rv = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                        GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
            return -1;
        }

        if (ngtcp2_crypto_gnutls_configure_client_session(session) != 0) {
            fprintf(stderr, "ngtcp2_crypto_gnutls_configure_client_session failed\n");
            return -1;
        }

        rv = gnutls_priority_set_direct(session, priority, NULL);
        if (rv != 0) {
            fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
                                            GNUTLS_HOOK_POST, hook_func);

        gnutls_session_set_ptr(session, &conn_ref);

        rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

        if (rv != 0) {
            fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

        if (!numeric_host(REMOTE_HOST))
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, REMOTE_HOST,
                                    strlen(REMOTE_HOST));
        else
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",
                                    strlen("localhost"));

        return 0;
    }


    int
    Connection::init_gnutls(Server& server)
    {
        fprintf(stderr, "Initializing server gnutls session\n");

        int rv = gnutls_certificate_allocate_credentials(&cred);

        if (rv == 0)
            rv = gnutls_certificate_set_x509_system_trust(cred);
        if (rv < 0) {
            fprintf(stderr, "cred init failed: %d: %s\n", rv, gnutls_strerror(rv));
            return -1;
        }

        rv = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                        GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
            return -1;
        }

        if (ngtcp2_crypto_gnutls_configure_server_session(session) != 0) {
            fprintf(stderr, "ngtcp2_crypto_gnutls_configure_server_session failed\n");
            return -1;
        }

        rv = gnutls_priority_set_direct(session, priority, NULL);
        if (rv != 0) {
            fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
                                            GNUTLS_HOOK_POST, hook_func);

        gnutls_session_set_ptr(session, &conn_ref);

        rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

        if (rv != 0) {
            fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

        if (!numeric_host(REMOTE_HOST))
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, REMOTE_HOST,
                                    strlen(REMOTE_HOST));
        else
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",
                                    strlen("localhost"));

        return 0;
    }


    int
    Connection::get_streams_available()
    {
        uint64_t open = ngtcp2_conn_get_streams_bidi_left(conn.get());
        if (open > std::numeric_limits<uint64_t>::max())
            return -1;
        return static_cast<int>(open);
    }


    int
    Connection::init(ngtcp2_settings &settings, ngtcp2_transport_params &params, ngtcp2_callbacks &callbacks)
    {
        auto loop = tun_endpoint.loop();
        io_trigger = loop->resource<uvw::AsyncHandle>();
        io_trigger->on<uvw::AsyncEvent>([this](auto&, auto&) { on_io_ready(); });
        
        retransmit_timer = loop->resource<uvw::TimerHandle>();
        retransmit_timer->on<uvw::TimerEvent>([this](auto&, auto&) 
        {
            fprintf(stderr, "Retransmit timer fired!\n");
            if (auto rv = ngtcp2_conn_handle_expiry(conn.get(), get_timestamp()); rv != 0)
            {
                fprintf(stderr, "Error: expiry handler invocation returned error code: %s\n", ngtcp2_strerror(rv));
                endpoint->close_connection(*this, rv);
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
        callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
        callbacks.rand = rand_cb;
        callbacks.recv_stream_data = recv_stream_data;
        callbacks.acked_stream_data_offset = acked_stream_data_offset;
        callbacks.stream_open = stream_open;
        callbacks.stream_close = stream_close_cb;
        callbacks.stream_reset = stream_reset_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

        ConnectionID dcid, scid;
        
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0) 
        {
            fprintf(stderr, "Error: gnutls_rnd failed\n");
            return -1;
        }

        scid.datalen = 8;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0) 
        {
            fprintf(stderr, "Error: gnutls_rnd failed\n");
            return -1;
        }

        ngtcp2_settings_default(&settings);

        settings.initial_ts = get_timestamp();
        settings.log_printf = log_printer;
        
        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 1024 * 1024;
        // Max concurrent streams supported on one connection
        params.initial_max_stream_data_uni = 0;
        params.initial_max_streams_bidi = 32;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to us)
        params.initial_max_stream_data_bidi_local = 64 * 1024;
        params.initial_max_stream_data_bidi_remote = 64 * 1024;

        return 0;
    }


    //  client conn
    Connection::Connection(
        Client& client, Tunnel& ep, const ConnectionID& scid, const Path& path, uint16_t tunnel_port)
        : tun_endpoint{ep}, client_tunnel_port{tunnel_port}, source_cid{scid}, dest_cid{ConnectionID::random()}, path{path}
    {
        fprintf(stderr, "Creating new client connection object\n");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks;
        ngtcp2_conn* connptr;
        pkt_type = CLIENT_TO_SERVER;
        endpoint = std::make_unique<Client>(client);
        
        init_gnutls(client);

        if (auto rv = init(settings, params, callbacks); rv != 0)
            fprintf(stderr, "Error: Client-based connection not created\n");

        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

        int rv = ngtcp2_conn_client_new(
            &connptr, 
            &dest_cid, 
            &source_cid, 
            path, 
            NGTCP2_PROTO_VER_V1, 
            &callbacks, 
            &settings, 
            &params, 
            nullptr, 
            this);

        conn_ref.get_conn = get_conn;
        conn_ref.user_data = &conn_ref;

        if (rv != 0) {
            throw std::runtime_error{"Failed to initialize client connection to server: "s + ngtcp2_strerror(rv)};
        }
        conn.reset(connptr);

        ngtcp2_conn_set_tls_native_handle(conn.get(), session);

        fprintf(stderr, "Successfully created new client connection object\n");
    }


    //  server conn
    Connection::Connection(
        Server& server, Tunnel& ep, const ConnectionID& cid, ngtcp2_pkt_hd& hdr, const Path& path)
        : tun_endpoint{ep}, source_cid{cid}, dest_cid{hdr.dcid}, path{path}
    {
        fprintf(stderr, "Creating new server connection object\n");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks;
        ngtcp2_cid dcid, scid;
        ngtcp2_conn* connptr;
        pkt_type = SERVER_TO_CLIENT;
        endpoint = std::make_unique<Server>(server);
        
        init_gnutls(server);

        if (auto rv = init(settings, params, callbacks); rv != 0)
            fprintf(stderr, "Error: Server-based connection not created\n");

        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

        int rv = ngtcp2_conn_server_new(
            &connptr, 
            &dcid, 
            &scid, 
            path, 
            NGTCP2_PROTO_VER_V1,
            &callbacks, 
            &settings, 
            &params, 
            nullptr, 
            this);

        conn_ref.get_conn = get_conn;
        conn_ref.user_data = &conn_ref;

        if (rv != 0) {
            throw std::runtime_error{"Failed to initialize server connection to client: "s + ngtcp2_strerror(rv)};
        }
        conn.reset(connptr);

        ngtcp2_conn_set_tls_native_handle(conn.get(), session);

        fprintf(stderr, "Successfully created new server connection object\n");
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

}   // namespace oxen::quic
