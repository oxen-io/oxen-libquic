#include "connection.hpp"

#include "format.hpp"

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/ip.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

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

    int on_recv_datagram(ngtcp2_conn* /* conn */, uint32_t flags, const uint8_t* data, size_t datalen, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->recv_datagram(
                {reinterpret_cast<const std::byte*>(data), datalen}, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    }

    int on_recv_stream_data(
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

    int on_acked_stream_data_offset(
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

    int on_stream_open(ngtcp2_conn* /*conn*/, int64_t stream_id, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_opened(stream_id);
    }

    int on_stream_close(
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

    int on_stream_reset(
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

    int extend_max_local_streams_bidi([[maybe_unused]] ngtcp2_conn* _conn, uint64_t /*max_streams*/, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        auto& conn = *static_cast<Connection*>(user_data);
        assert(_conn == conn);

        if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn); remaining > 0)
            conn.check_pending_streams(remaining);

        return 0;
    }

    ConnectionID::ConnectionID(const uint8_t* cid, size_t length)
    {
        assert(length <= NGTCP2_MAX_CIDLEN);
        datalen = length;
        std::memmove(data, cid, datalen);
    }

    ConnectionID ConnectionID::random()
    {
        ConnectionID cid;
        cid.datalen = static_cast<size_t>(NGTCP2_MAX_CIDLEN);
        gnutls_rnd(GNUTLS_RND_RANDOM, cid.data, cid.datalen);
        return cid;
    }

    std::string ConnectionID::to_string() const
    {
        return "{:02x}"_format(fmt::join(std::begin(data), std::begin(data) + datalen, ""));
    }

    uint64_t Connection::next_dgram_id()
    {
        _last_dgram_id += _increment;
        return _last_dgram_id;
    }

    void Connection::packet_io_ready()
    {
        event_active(packet_io_trigger.get(), 0, 0);
    }

    // note: this does not need to return anything, it is never called except in on_stream_available
    // First, we check the list of pending streams on deck to see if they're ready for broadcast. If
    // so, we move them to the streams map, where they will get picked up by flush_streams and dump
    // their buffers. If none are ready, we keep chugging along and make another stream as usual. Though
    // if none of the pending streams are ready, the new stream really shouldn't be ready, but here we are
    void Connection::check_pending_streams(int available)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        int popped = 0;

        while (!pending_streams.empty() && popped < available)
        {
            auto& str = pending_streams.front();

            if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &str->_stream_id, str.get()); rv == 0)
            {
                log::debug(log_cat, "Stream [ID:{}] ready for broadcast, moving out of pending streams", str->_stream_id);
                str->set_ready();
                popped += 1;
                streams[str->_stream_id] = std::move(str);
                pending_streams.pop_front();
            }
            else
                return;
        }
    }

    std::shared_ptr<Stream> Connection::get_new_stream(stream_data_callback data_cb, stream_close_callback close_cb)
    {
        if (!data_cb)
            data_cb = context->stream_data_cb;

        auto stream = std::make_shared<Stream>(*this, _endpoint, std::move(data_cb), std::move(close_cb));

        if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &stream->_stream_id, stream.get()); rv != 0)
        {
            log::warning(log_cat, "Stream not ready [Code: {}]; adding to pending streams list", ngtcp2_strerror(rv));
            stream->set_not_ready();
            pending_streams.push_back(std::move(stream));
            return pending_streams.back();
        }
        else
        {
            log::debug(log_cat, "Stream {} successfully created; ready to broadcast", stream->_stream_id);
            stream->set_ready();
            auto& strm = streams[stream->_stream_id];
            strm = std::move(stream);
            return strm;
        }
    }

    void Connection::call_closing()
    {
        if (!on_closing)
            return;

        log::trace(log_cat, "Calling Connection::on_closing for CID: {}", _source_cid);
        on_closing(*this);
        on_closing = nullptr;
    }

    void Connection::on_packet_io_ready()
    {
        auto ts = get_time();
        flush_packets(ts);
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

    int64_t sent_counter = 0;

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

        sent_counter += n_packets;

        auto rv = endpoint().send_packets(_path.remote, send_buffer.data(), send_buffer_size.data(), send_ecn, n_packets);

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
            log::critical(log_cat, "FIXME: close connection here?");  // FIXME TODO
            if (pkt_updater)
                pkt_updater->cancel();
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
            log::trace(log_cat, "Skipping this flush_streams call; we still have {} queued packets", n_packets);
            return;
        }

        std::list<IOChannel*> channels;
        if (!streams.empty())
        {
            // Start from a random stream so that we aren't favouring early streams by potentially
            // giving them more opportunities to send packets.
            auto mid = std::next(
                    streams.begin(), std::uniform_int_distribution<size_t>{0, streams.size() - 1}(stream_start_rng));

            for (auto it = mid; it != streams.end(); ++it)
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

            for (auto it = streams.begin(); it != mid; ++it)
            {
                auto& stream_ptr = it->second;
                if (stream_ptr and not stream_ptr->_sent_fin)
                    channels.push_back(stream_ptr.get());
            }
        }
        else if (not datagrams->is_empty())
        {
            // if we have only datagrams to send, then we should probably do that
            if (not datagrams->is_empty())
            {
                log::trace(log_cat, "Datagram channel has things to send");
                channels.push_back(datagrams.get());
            }
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

            std::vector<ngtcp2_vec> bufs = source->pending();

            // this block will execute all "real" streams plus the "pseudo stream" of ID -1 to finish
            // off any packets that need to be sent
            if (source->is_stream())
            {
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
                nwrite = ngtcp2_conn_writev_datagram(
                        conn.get(),
                        _path,
                        &pkt_info,
                        buf_pos,
                        MAX_PMTUD_UDP_PAYLOAD,
                        &datagram_accepted,
                        flags |= NGTCP2_WRITE_DATAGRAM_FLAG_MORE,
                        0,
                        bufs.data(),
                        1,
                        ts);

                log::debug(log_cat, "ngtcp2_conn_writev_datagram returned a value of {}", nwrite);

                if (datagram_accepted != 0)
                    datagrams->user_buffers.pop_front();
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
                    _endpoint.call([this, rv = nwrite]() {
                        log::info(log_cat, "Endpoint signaled by connection (CID: {}) to kill it", _source_cid);
                        _endpoint.close_connection(*this, rv, ngtcp2_strerror(rv));
                    });
                    return;
                }
                else if (nwrite == NGTCP2_ERR_WRITE_MORE)
                {
                    if (source->is_stream())
                    {
                        log::trace(log_cat, "Consumed {} bytes from stream {} and have space left", ndatalen, stream_id);
                        assert(ndatalen >= 0);
                        if (stream_id != -1)
                            source->wrote(ndatalen);
                    }
                }
                else
                {
                    log::debug(log_cat, "Non-fatal ngtcp2 error: {}", ngtcp2_strerror(nwrite));
                }

                continue;
            }

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
        log::debug(log_cat, "Exiting flush_streams()");
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

        auto delta = exp_ns * 1ns - ts.time_since_epoch();
        log::trace(log_cat, "Expiry delta: {}ns", delta.count());

        timeval* tv_ptr = nullptr;
        timeval tv;
        if (delta > 0s)
        {
            delta += 999ns;  // Round up to the next µs (libevent timers have µs precision)
            tv.tv_sec = delta / 1s;
            tv.tv_usec = (delta % 1s) / 1us;
            tv_ptr = &tv;
        }
        event_add(packet_retransmit_timer.get(), tv_ptr);
    }

    const std::shared_ptr<Stream>& Connection::get_stream(int64_t ID) const
    {
        return streams.at(ID);
    }

    int Connection::stream_opened(int64_t id)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::info(log_cat, "New stream ID:{}", id);

        auto stream = std::make_shared<Stream>(*this, _endpoint, context->stream_data_cb, context->stream_close_cb, id);
        stream->set_ready();

        log::debug(log_cat, "Local endpoint creating stream to match remote");

        if (uint64_t app_err_code = context->stream_open_cb ? context->stream_open_cb(*stream) : 0; app_err_code != 0)
        {
            log::info(log_cat, "stream_open_callback returned error code {}, closing stream {}", app_err_code, id);
            assert(endpoint().in_event_loop());
            stream->close(app_err_code);
            return 0;
        }

        [[maybe_unused]] auto [it, ins] = streams.emplace(id, std::move(stream));
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
        const bool was_closing = stream._is_closing;
        stream._is_closing = stream.is_shutdown = true;

        if (!was_closing && stream.close_callback)
        {
            log::trace(log_cat, "Invoking stream close callback");
            stream.close_callback(stream, app_code);
        }

        log::info(log_cat, "Erasing stream {}", id);
        streams.erase(it);

        if (!ngtcp2_conn_is_local_stream(conn.get(), id))
            ngtcp2_conn_extend_max_streams_bidi(conn.get(), 1);

        packet_io_ready();
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
            log::debug(log_cat, "Stream (ID: {}) has no user-supplied data callback", str->_stream_id);
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
                        str->_stream_id,
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
                        str->_stream_id,
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
            log::info(log_cat, "Stream {} closed by remote", str->_stream_id);
            // no clean up, close_cb called after this
        }
        else
        {
            ngtcp2_conn_extend_max_stream_offset(conn.get(), id, data.size());
            ngtcp2_conn_extend_max_offset(conn.get(), data.size());
        }

        return 0;
    }

    int Connection::recv_datagram(bstring_view data, bool fin)
    {
        log::trace(log_cat, "Connection (CID: {}) received datagram: {}", _source_cid, buffer_printer{data});

        // append received datagram to tetris_buffer if packet_splitting is enabled
        if (_packet_splitting)
        {
            // TODO: should this logic go earlier in the process inside handle_packet?
        }

        if (!datagrams->dgram_data_cb)
            log::debug(log_cat, "Connection (CID: {}) has no endpoint-supplied datagram data callback", _source_cid);
        else
        {
            bool good = false;

            try
            {
                datagrams->dgram_data_cb(data);
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
                // TODO: do we want to close the entire connection on user-supplied callback failure? WHat about in
                // the above exceptions?
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

    void Connection::send_datagram(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!_datagrams_enabled)
            throw std::runtime_error{"Endpoint not configured for datagram IO"};

        datagrams->send(data, std::move(keep_alive));
    }

    int Connection::get_streams_available() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint64_t open = ngtcp2_conn_get_streams_bidi_left(conn.get());
        if (open > std::numeric_limits<uint64_t>::max())
            return -1;
        return open;
    }

    size_t Connection::get_max_datagram_size() const
    {
        // If policy is greedy, we can take in doubel the datagram size
        size_t multiple = (packet_splitting_policy() == Splitting::GREEDY) ? 2 : 1;

        if (_datagrams_enabled)
            return multiple * (ngtcp2_conn_get_path_max_tx_udp_payload_size(conn.get()) - DATAGRAM_OVERHEAD);
        return 0;
    }

    int Connection::init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks)
    {
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
                        log::warning(
                                log_cat, "Error: expiry handler invocation returned error code: {}", ngtcp2_strerror(rv));
                        self.endpoint().close_connection(self, rv);
                        return;
                    }
                    self.on_packet_io_ready();
                },
                this));

        event_add(packet_retransmit_timer.get(), nullptr);

        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = on_recv_stream_data;
        callbacks.acked_stream_data_offset = on_acked_stream_data_offset;
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
        callbacks.stream_open = on_stream_open;

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

        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 15_Mi;
        // Max concurrent streams supported on one connection
        params.initial_max_streams_uni = 0;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to us)
        params.initial_max_stream_data_bidi_local = 6_Mi;
        params.initial_max_stream_data_bidi_remote = 6_Mi;
        params.initial_max_stream_data_uni = 6_Mi;
        params.max_idle_timeout = std::chrono::nanoseconds(5min).count();
        params.active_connection_id_limit = 8;

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
            callbacks.recv_datagram = on_recv_datagram;
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
            const ConnectionID& scid,
            const ConnectionID& dcid,
            const Path& path,
            std::shared_ptr<IOContext> ctx,
            ngtcp2_pkt_hd* hdr) :
            _endpoint{ep},
            context{std::move(ctx)},
            dir{context->dir},
            _source_cid{scid},
            _dest_cid{dcid},
            _path{path},
            _max_streams{context->config.max_streams ? context->config.max_streams : DEFAULT_MAX_BIDI_STREAMS},
            _datagrams_enabled{context->config.datagram_support},
            _packet_splitting{context->config.split_packet},
            _policy{context->config.policy},
            tls_creds{context->tls_creds}
    {
        datagrams = std::make_shared<DatagramIO>(*this, _endpoint, ep.dgram_recv_cb);
        pseudo_stream = std::make_shared<Stream>(*this, _endpoint, -1);

        const auto is_outbound = (dir == Direction::OUTBOUND);
        const auto d_str = is_outbound ? "outbound"s : "inbound"s;
        log::trace(log_cat, "Creating new {} connection object", d_str);

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;
        int rv = 0;

        if (rv = init(settings, params, callbacks); rv != 0)
            log::critical(log_cat, "Error: {} connection not created", d_str);

        if (is_outbound)
        {
            callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
            callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

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
            params.original_dcid = ngtcp2_cid{hdr->dcid};
            params.original_dcid_present = 1;
            settings.token = hdr->token;

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

        tls_session = tls_creds->make_session(is_outbound);
        tls_session->conn_ref.get_conn = get_conn;
        tls_session->conn_ref.user_data = this;
        ngtcp2_conn_set_tls_native_handle(connptr, tls_session->get_session());

        conn.reset(connptr);

        if (rv != 0)
        {
            throw std::runtime_error{"Failed to initialize connection object: "s + ngtcp2_strerror(rv)};
        }

        log::info(log_cat, "Successfully created new {} connection object", d_str);
    }

    std::shared_ptr<Connection> Connection::make_conn(
            Endpoint& ep,
            const ConnectionID& scid,
            const ConnectionID& dcid,
            const Path& path,
            std::shared_ptr<IOContext> ctx,
            ngtcp2_pkt_hd* hdr)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        std::shared_ptr<Connection> conn{new Connection{ep, scid, dcid, path, std::move(ctx), hdr}};

        conn->packet_io_ready();

        return conn;
    }

}  // namespace oxen::quic
