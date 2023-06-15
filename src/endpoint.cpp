#include "endpoint.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>
#ifdef __linux__
#include <netinet/udp.h>
#endif
}

#include <cstddef>
#include <optional>
#include <uvw.hpp>

#include "connection.hpp"
#include "handler.hpp"
#include "internal.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Endpoint::Endpoint(std::shared_ptr<Handler>& quic_manager)
    {
        handler = quic_manager;

        expiry_timer = get_loop()->resource<uvw::timer_handle>();
        expiry_timer->on<uvw::timer_event>([this](const auto&, auto&) { check_timeouts(); });
        expiry_timer->start(250ms, 250ms);

        log::info(log_cat, "Successfully created QUIC endpoint");
    };

    // Endpoint::~Endpoint()
    // {
    //     log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    //     shutdown();

    //     if (expiry_timer)
    //         expiry_timer->close();
    // }

    // adds async_cb to all connections; intended use is async shutdown of connections
    void Endpoint::call_async_all(async_callback_t async_cb)
    {
        for (const auto& c : conns)
            c.second->io_trigger->on<uvw::async_event>(async_cb);
    }

    std::list<std::pair<ConnectionID, Address>> Endpoint::get_conn_addrs()
    {
        std::list<std::pair<ConnectionID, Address>> ret{};

        for (const auto& c : conns)
            ret.emplace_back(c.first, c.second->remote);

        return ret;
    }

    void Endpoint::close_conns()
    {
        for (const auto& c : conns)
        {
            close_connection(*c.second.get());
        }
    }

    std::shared_ptr<uvw::loop> Endpoint::get_loop()
    {
        return (handler->ev_loop) ? handler->ev_loop : nullptr;
    }

    void Endpoint::handle_packet(Packet& pkt)
    {
        auto dcid_opt = handle_initial_packet(pkt);

        if (!dcid_opt)
        {
            log::warning(log_cat, "Error: initial packet handling failed");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        log::debug(log_cat, "Incoming connection ID: {}", *dcid.data);
        auto cptr = get_conn(dcid);

        if (!cptr)
        {
            cptr = accept_initial_connection(pkt, dcid);

            if (!cptr)
            {
                log::warning(log_cat, "Error: connection could not be created");
                return;
            }
        }

        handle_conn_packet(*cptr, pkt);
        return;
    }

    void Endpoint::close_connection(Connection& conn, int code, std::string_view msg)
    {
        log::debug(log_cat, "Closing connection (CID: {})", *conn.source_cid.data);

        if (conn.closing || conn.draining)
            return;

        if (code == NGTCP2_ERR_IDLE_CLOSE)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now without close "
                    "packet",
                    *conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now with close packet",
                    *conn.source_cid.data);
        }

        ngtcp2_ccerr err;
        ngtcp2_ccerr_set_liberr(&err, code, reinterpret_cast<uint8_t*>(const_cast<char*>(msg.data())), msg.size());

        conn.conn_buffer.resize(max_pkt_size);
        Path path;
        ngtcp2_pkt_info pkt_info{};

        auto written = ngtcp2_conn_write_connection_close(
                conn, path, &pkt_info, u8data(conn.conn_buffer), conn.conn_buffer.size(), &err, get_timestamp());

        if (written <= 0)
        {
            log::warning(
                    log_cat,
                    "Error: Failed to write connection close packet: {}",
                    (written < 0) ? strerror(written) : "[Error Unknown: closing pkt is 0 bytes?]"s);

            delete_connection(conn.source_cid);
            return;
        }
        // ensure we have enough write space
        assert(written <= (long)conn.conn_buffer.size());

        if (auto rv = send_packet(conn.path, conn.conn_buffer); rv.failure())
        {
            log::warning(
                    log_cat,
                    "Error: failed to send close packet [code: {}]; removing connection [CID: {}]",
                    rv.str(),
                    *conn.source_cid.data);
            delete_connection(conn.source_cid);
        }
    }

    void Endpoint::delete_connection(const ConnectionID& cid)
    {
        auto target = conns.find(cid);
        if (target == conns.end())
        {
            log::warning(log_cat, "Error: could not delete connection [ID: {}]; could not find", *cid.data);
            return;
        }

        auto c_ptr = target->second.get();

        if (c_ptr->on_closing)
        {
            c_ptr->on_closing(*c_ptr);
            c_ptr->on_closing = nullptr;
        }

        conns.erase(target);
    }

    std::optional<ConnectionID> Endpoint::handle_initial_packet(Packet& pkt)
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

    void Endpoint::handle_conn_packet(Connection& conn, Packet& pkt)
    {
        if (auto rv = ngtcp2_conn_in_closing_period(conn); rv != 0)
        {
            log::debug(
                    log_cat, "Error: connection (CID: {}) is in closing period; dropping connection", *conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        if (conn.draining)
        {
            log::debug(log_cat, "Error: connection is already draining; dropping");
        }

        if (read_packet(conn, pkt).success())
            log::trace(log_cat, "done with incoming packet");
        else
            log::trace(log_cat, "read packet failed");  // error will be already logged
    }

    io_result Endpoint::read_packet(Connection& conn, Packet& pkt)
    {
        auto ts = get_timestamp();
        auto rv = ngtcp2_conn_read_pkt(conn, pkt.path, &pkt.pkt_info, u8data(pkt.data), pkt.data.size(), ts);

        switch (rv)
        {
            case 0:
                conn.io_ready();
                break;
            case NGTCP2_ERR_DRAINING:
                log::debug(log_cat, "Draining connection {}", *conn.source_cid.data);
                break;
            case NGTCP2_ERR_PROTO:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                close_connection(conn, rv, "ERR_PROTO"sv);
                break;
            case NGTCP2_ERR_DROP_CONN:
                // drop connection without calling ngtcp2_conn_write_connection_close()
                log::debug(log_cat, "Dropping connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                delete_connection(conn.source_cid);
                break;
            case NGTCP2_ERR_CRYPTO:
                // drop conn without calling ngtcp2_conn_write_connection_close()
                log::debug(
                        log_cat,
                        "Dropping connection {} due to error {} (code: {})",
                        *conn.source_cid.data,
                        ngtcp2_conn_get_tls_alert(conn),
                        ngtcp2_strerror(rv));
                delete_connection(conn.source_cid);
                break;
            default:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                close_connection(conn, rv, ngtcp2_strerror(rv));
                break;
        }

        return io_result::ngtcp2(rv);
    }

    // We support different compilation modes for trying different methods of UDP sending by setting
    // these defines; these shouldn't be set directly but rather through the cmake -DLIBQUIC_SEND
    // option.  Exactly one of these must be defined.
    //
    // OXEN_LIBQUIC_UDP_LIBUV_QUEUING -- does everything through udp_send, which involves setting up
    // packet queuing.  This is not the default because, in practice, it's slower than just sending
    // directly.
    // CMake option: -DLIBQUIC_SEND=libuv_queue
    //
    // OXEN_LIBQUIC_UDP_LIBUV_TRY -- use libuv udp_try_send calls to try to send a packet, with or
    // own internal rescheduling when we block.
    // CMake option: -DLIBQUIC_SEND=libuv_try
    //
    // OXEN_LIBQUIC_UDP_GSO -- use sendmmsg and GSO to batch-send packets.  Only works on
    // Linux.
    // CMake option: -DLIBQUIC_SEND=gso
    //
    // OXEN_LIBQUIC_UDP_SENDMMSG -- use sendmmsg (but not GSO) to batch-send packets.  Only works on
    // Linux and FreeBSD.
    // CMake option: -DLIBQUIC_SEND=sendmmsg

#if (defined(OXEN_LIBQUIC_UDP_LIBUV_QUEUING) + defined(OXEN_LIBQUIC_UDP_LIBUV_TRY) + defined(OXEN_LIBQUIC_UDP_GSO) + \
     defined(OXEN_LIBQUIC_UDP_SENDMMSG)) != 1
#error You must define (exactly) one of OXEN_LIBQUIC_UDP_LIBUV_QUEUING OXEN_LIBQUIC_UDP_LIBUV_TRY OXEN_LIBQUIC_UDP_GSO OXEN_LIBQUIC_UDP_SENDMMSG
#endif

    namespace
    {
        struct packet_storage
        {
            uv_udp_send_t req;
            std::array<char, max_pkt_size> buf;
            std::function<void()> callback;

            ~packet_storage()
            {
                if (callback)
                    callback();
            }
        };
        extern "C" void packet_storage_release(uv_udp_send_t* send, int code)
        {
            delete static_cast<packet_storage*>(send->data);
        }
    }  // namespace

    io_result Endpoint::send_packet_libuv(Path& p, const char* buf, size_t bufsize, std::function<void()> callback)
    {
        auto* packet_data = new packet_storage{};
        std::memcpy(packet_data->buf.data(), buf, bufsize);
        packet_data->req.data = packet_data;
        packet_data->callback = std::move(callback);

        uv_buf_t uv_buf;
        uv_buf.base = packet_data->buf.data();
        uv_buf.len = bufsize;

        auto handle = get_handle(p);
        assert(handle);

        auto rv = uv_udp_send(&packet_data->req, handle.get(), &uv_buf, 1, p.remote, packet_storage_release);
        if (rv != 0)
        {
            // This is a libuv error, which means it isn't calling our release so we have to do it.
            // (This cannot be a EAGAIN-type error, though, because the above call queues on blocked
            // IO).
            delete packet_data;
            auto res = io_result::libuv(rv);
            if (res.blocked())
            {
                // We shouldn't get this, and mustn't return it
                log::warning(log_cat, "Unexpected blocked result from uv_udp_send");
                return io_result{EINVAL};
            }
            log::warning(log_cat, "Failed to send packet via libuv: {}", uv_strerror(rv));
            return res;
        }

        return io_result{};
    }

    io_result Endpoint::send_packets(Path& p, char* buf, size_t* bufsize, size_t& n_pkts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        assert(n_pkts >= 1 && n_pkts <= MAX_BATCH);

        log::trace(log_cat, "Sending UDP packet to {}...", p.remote);

#ifdef OXEN_LIBQUIC_UDP_LIBUV_QUEUING
        static_assert(MAX_BATCH == 1);
        assert(n_pkts == 1);
        assert(bufsize[0] > 0);
        n_pkts = 0;  // We are either sending, or exiting via error (*not* including blocking) so
                     // either way reset this to zero.
        send_packet_libuv(p, buf, bufsize[0]);

#else
        auto handle = get_handle(p);
        assert(handle);

#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
        uv_os_fd_t fd;
        int rv = uv_fileno(reinterpret_cast<uv_handle_t*>(handle.get()), &fd);
        if (rv != 0)
            return io_result{EBADF};
        std::array<mmsghdr, MAX_BATCH> msgs{};
        std::array<iovec, MAX_BATCH> iovs{};
        auto* next_buf = buf;

#ifdef OXEN_LIBQUIC_UDP_GSO
#define OXEN_LIBQUIC_SEND_TYPE "GSO"

        // With GSO, we use *one* sendmmsg call which can contain multiple batches of packets; each
        // batch is of size n, where each of the n have the same size.
        //
        // We could have up to the full MAX_BATCH, with the worst case being every packet being a
        // different size than the one before it.
        std::array<std::array<char, CMSG_SPACE(sizeof(uint16_t))>, MAX_BATCH> controls{};
        std::array<uint16_t, MAX_BATCH> gso_sizes{};   // Size of each of the packets
        std::array<uint16_t, MAX_BATCH> gso_counts{};  // Number of packets

        unsigned int msg_count = 0;
        for (int i = 0; i < n_pkts; i++)
        {
            auto& gso_size = gso_sizes[msg_count];
            auto& gso_count = gso_counts[msg_count];
            gso_count++;
            if (gso_size == 0)
                gso_size = bufsize[i];  // new batch

            if (i < n_pkts - 1 && bufsize[i + 1] == gso_size)
                continue;  // The next one can be batched with us

            auto& iov = iovs[msg_count];
            auto& msg = msgs[msg_count];
            iov.iov_base = next_buf;
            iov.iov_len = gso_count * gso_size;
            next_buf += iov.iov_len;
            msg_count++;
            auto& hdr = msg.msg_hdr;
            hdr.msg_iov = &iov;
            hdr.msg_iovlen = 1;
            hdr.msg_name = const_cast<sockaddr*>(static_cast<const sockaddr*>(p.remote));
            hdr.msg_namelen = p.remote.socklen();
            if (gso_count > 1)
            {
                auto& control = controls[msg_count];
                hdr.msg_control = control.data();
                hdr.msg_controllen = control.size();
                auto* cm = CMSG_FIRSTHDR(&hdr);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type = UDP_SEGMENT;
                cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                *reinterpret_cast<uint16_t*>(CMSG_DATA(cm)) = gso_size;
            }
        }

        do
        {
            rv = sendmmsg(fd, msgs.data(), msg_count, 0);
        } while (rv == -1 && errno == EINTR);

        if (rv == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            n_pkts = 0;  // Drop the packets since we got some serious error
            return io_result{errno};
        }

        // Figure out number of packets we actually sent:
        // rv is the number of `msgs` elements that were updated; within each, the `.msg_len` field
        // has been updated to the number of bytes that were sent (which we need to use to figure
        // out how many actual batched packets went out from our batch-of-batches).
        size_t sent = 0;
#ifndef NDEBUG
        bool found_unsent = false;
#endif
        if (rv > 0)
        {
            for (unsigned int i = 0; i < msg_count; i++)
            {
                if (msgs[i].msg_len < iovs[i].iov_len)
                {
#ifndef NDEBUG
                    // Once we encounter some unsent we expect to miss everything after that (i.e. we
                    // are expecting that contiguous packets 0 through X are accepted and X+1 through
                    // the end were not): so if this batch was partially sent then we shouldn't have
                    // been any partial sends before it.
                    assert(!found_unsent || msgs[i].msg_len == 0);
                    found_unsent = true;
#endif

                    // Partial packets consumed should be impossible:
                    assert(msgs[i].msg_len % gso_sizes[i] == 0);
                    sent += msgs[i].msg_len / gso_sizes[i];
                }
                else
                {
                    assert(!found_unsent);
                    sent += gso_counts[i];
                }
            }
        }

        io_result ret{rv == -1 ? errno : 0};

#else  // sendmmsg, but not GSO
#define OXEN_LIBQUIC_SEND_TYPE "sendmmsg"

        for (int i = 0; i < n_pkts; i++)
        {
            assert(bufsize[i] > 0);

            iovs[i].iov_base = next_buf;
            iovs[i].iov_len = bufsize[i];
            next_buf += bufsize[i];

            auto& hdr = msgs[i].msg_hdr;
            hdr.msg_iov = &iovs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_name = const_cast<sockaddr*>(static_cast<const sockaddr*>(p.remote));
            hdr.msg_namelen = p.remote.socklen();
        }

        do
        {
            rv = sendmmsg(fd, msgs.data(), n_pkts, MSG_DONTWAIT);
        } while (rv == -1 && errno == EINTR);

        if (rv == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            n_pkts = 0;  // Serious error; drop the packets
            return io_result{errno};
        }

        size_t sent = rv >= 0 ? rv : 0;

        io_result ret{rv == -1 ? errno : 0};

#endif

#elif defined(OXEN_LIBQUIC_UDP_LIBUV_TRY)  // No sendmmsg at all, instead we use libuv's try_send for each packet
#define OXEN_LIBQUIC_SEND_TYPE "uv_udp_try_send"
        uv_buf_t uv_buf;
        uv_buf.base = buf;
        int sent = 0;
        io_result ret{};
        for (int i = 0; i < n_pkts; ++i)
        {
            assert(bufsize[i] > 0);

            uv_buf.len = bufsize[i];

            auto rv = uv_udp_try_send(handle.get(), &uv_buf, 1, p.remote);
            assert(rv == bufsize[i] || rv < 0);
            if (rv < 0)
            {
                ret = io_result::libuv(rv);
                break;
            }

            sent++;
            uv_buf.base += uv_buf.len;
        }
#else
#error Unknown quic send type!
#endif

        if (ret.failure() && !ret.blocked())
        {
            log::error(log_cat, "Error sending packets to {}: {}", p.remote, ret.str());
            n_pkts = 0;  // Drop any packets, as we had a serious error
            return ret;
        }

        if (sent < n_pkts)
        {
            if (sent == 0)  // Didn't send *any* packets, i.e. we got entirely blocked
                log::debug(log_cat, OXEN_LIBQUIC_SEND_TYPE " sent none of {}", n_pkts);

            else
            {
                // We sent some but not all, so shift the unsent packets back to the beginning of buf/bufsize
                log::debug(log_cat, OXEN_LIBQUIC_SEND_TYPE " undersent {}/{}", sent, n_pkts);
                size_t offset = std::accumulate(bufsize, bufsize + sent, size_t{0});
                size_t len = std::accumulate(bufsize + sent, bufsize + n_pkts, size_t{0});
                std::memmove(buf, buf + offset, len);
                std::copy(bufsize + sent, bufsize + n_pkts, bufsize);
                n_pkts -= sent;
            }

            // We always return EAGAIN if we failed to send all, even if that isn't strictly what we got
            // back as the return value (sendmmsg gives back a non-error on *partial* success).
            return io_result{EAGAIN};
        }
        else
            n_pkts = 0;

        return ret;
#endif  // not LIBUV queuing
    }

    namespace
    {
        struct send_helper
        {
            uv_udp_send_t req;
            std::array<char, max_pkt_size> data;
        };
    }  // namespace

    io_result Endpoint::send_packet(Path& p, bstring_view data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto handle = get_handle(p);

        assert(handle);

        auto helper = new send_helper{};
        helper->req.data = helper;
        std::memcpy(helper->data.data(), data.data(), data.size());
        const uv_buf_t uv_buf{helper->data.data(), data.size()};

        log::debug(log_cat, "Sending UDP packet to {}...", p.remote);
        uv_udp_send(&helper->req, handle.get(), &uv_buf, 1, p.remote, [](uv_udp_send_t* req, int status) {
            delete static_cast<send_helper*>(req->data);
            log::trace(log_cat, "Packet sent with status {}", status);
        });

        return io_result{0};
    }

    void Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, Path& p)
    {
        auto randgen = make_mt19937();
        std::array<std::byte, max_pkt_size> _buf;
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto nwrite = ngtcp2_pkt_write_version_negotiation(
                u8data(_buf),
                _buf.size(),
                std::uniform_int_distribution<uint8_t>()(randgen),
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

        send_packet(p, bstring_view{_buf.data(), static_cast<size_t>(nwrite)});
    }

    void Endpoint::check_timeouts()
    {
        auto now = get_timestamp();

        while (!draining.empty() && draining.front().second < now)
        {
            if (auto it = conns.find(draining.front().first); it != conns.end())
            {
                log::debug(log_cat, "Deleting connection {}", *it->first.data);
                conns.erase(it);
            }
            draining.pop();
        }
    }

    Connection* Endpoint::get_conn(ConnectionID ID)
    {
        auto it = conns.find(ID);

        if (it == conns.end())
            return nullptr;

        return it->second.get();
    }

    Connection* Endpoint::get_conn(const Address& addr)
    {
        for (const auto& c : conns)
        {
            if (c.second->remote == addr)
                return c.second.get();
        }

        return nullptr;
    }
}  // namespace oxen::quic
