#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#endif

extern "C"
{

#ifdef __linux__
#include <netinet/udp.h>
#endif

#include <fcntl.h>
#include <unistd.h>
}

#include <system_error>

#include "internal.hpp"
#include "udp.hpp"

namespace oxen::quic
{

#ifndef _WIN32

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    static int check_rv(int rv)
    {
        if (rv == -1)
            throw std::system_error{errno, std::system_category()};
        return rv;
    }

    Packet::Packet(const Address& local, bstring_view data, msghdr& hdr) :
            path{local, {static_cast<const sockaddr*>(hdr.msg_name), hdr.msg_namelen}}, data{data}
    {
        // ECN flag:
        assert(path.remote.is_ipv4() || path.remote.is_ipv6());
        for (auto cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg))
        {
            if ((path.remote.is_ipv4() ? (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
                                       : (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) &&
                cmsg->cmsg_len > 0)
            {
                pkt_info.ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg));
                break;
            }
        }
    }

    UDPSocket::UDPSocket(event_base* ev_loop, const Address& addr, receive_callback_t on_receive) :
            ev_{ev_loop}, receive_callback_{std::move(on_receive)}
    {
        assert(ev_);

        if (!receive_callback_)
            throw std::logic_error{"UDPSocket construction requires a non-empty receive callback"};

        sock_ = check_rv(socket(addr.is_ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM, 0));

        check_rv(bind(sock_, addr, addr.socklen()));
        check_rv(getsockname(sock_, bound_, bound_.socklen_ptr()));
        check_rv(fcntl(sock_, F_SETFL, O_NONBLOCK));
        unsigned int on = 1;
        if (addr.is_ipv6())
            check_rv(setsockopt(sock_, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on)));
        else
            check_rv(setsockopt(sock_, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)));
        set_ecn();

        rev_.reset(event_new(
                ev_,
                sock_,
                EV_READ | EV_PERSIST,
                [](socket_t, short, void* self) { static_cast<UDPSocket*>(self)->receive(); },
                this));
        event_add(rev_.get(), nullptr);

        wev_.reset(event_new(
                ev_,
                sock_,
                EV_WRITE,
                [](socket_t, short, void* self_) {
                    auto* self = static_cast<UDPSocket*>(self_);
                    auto callbacks = std::move(self->writeable_callbacks_);
                    for (const auto& f : callbacks)
                        f();
                },
                this));
        // Don't event_add wev_ now: we only activate wev_ when something asks to be tied to writeability
    }

    UDPSocket::~UDPSocket()
    {
        if (sock_ != -1)
            ::close(sock_);
    }

    // Updates the socket's ECN value to `ecn_`.
    void UDPSocket::set_ecn()
    {
        int rv;
        if (bound_.is_ipv6())
            rv = setsockopt(sock_, IPPROTO_IPV6, IPV6_TCLASS, &ecn_, sizeof(ecn_));
        else
            rv = setsockopt(sock_, IPPROTO_IP, IP_TOS, &ecn_, sizeof(ecn_));
        if (rv == -1)  // Just warn; this isn't fatal
            log::warning(log_cat, "Failed to update ECN on socket: {}", strerror(errno));
    }

    void UDPSocket::process_packet(bstring_view payload, msghdr& hdr)
    {
        if (payload.empty())
        {
            // This is unexpected, and not something a proper libquic client would ever send so
            // just drop it.
            log::warning(log_cat, "Dropping empty UDP packet");
            return;
        }

        // This flag means the packet payload couldn't fit in max_payload_size, but that should
        // never happen (at least as long as the other end is a proper libquic client).
        if (hdr.msg_flags & MSG_TRUNC)
        {
            log::warning(log_cat, "Dropping truncated UDP packet");
            return;
        }

        receive_callback_(Packet{bound_, payload, hdr});
    }

    io_result UDPSocket::receive()
    {
        assert(sock_ != -1);

#ifdef OXEN_LIBQUIC_RECVMMSG
        std::array<sockaddr_in6, DATAGRAM_BATCH_SIZE> peers;
        std::array<iovec, DATAGRAM_BATCH_SIZE> iovs;
        std::array<mmsghdr, DATAGRAM_BATCH_SIZE> msgs = {};

        std::array<std::array<std::byte, max_payload_size>, DATAGRAM_BATCH_SIZE> data;

        for (size_t i = 0; i < DATAGRAM_BATCH_SIZE; i++)
        {
            iovs[i].iov_base = data[i].data();
            iovs[i].iov_len = data[i].size();
            auto& h = msgs[i].msg_hdr;
            h.msg_iov = &iovs[i];
            h.msg_iovlen = 1;
            h.msg_name = &peers[i];
            h.msg_namelen = sizeof(peers[i]);
        }

        size_t count = 0;
        do
        {
            int nread;
            do
            {
                nread = recvmmsg(sock_, msgs.data(), msgs.size(), 0, nullptr);
            } while (nread == -1 && errno == EINTR);

            if (nread == 0)  // No packets available to read
                return io_result{};

            if (nread < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return io_result{};
                return io_result{errno};
            }

            for (int i = 0; i < nread; i++)
                process_packet(bstring_view{data[i].data(), msgs[i].msg_len}, msgs[i].msg_hdr);

            count += nread;

            if (nread < static_cast<int>(DATAGRAM_BATCH_SIZE))
                // We didn't fill the recvmmsg array so must be done
                return io_result{};

        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};

#else  // no recvmmsg

        sockaddr_in6 peer{};
        std::array<std::byte, max_payload_size> data;
        iovec iov;
        iov.iov_base = data.data();
        iov.iov_len = data.size();
        msghdr hdr{};
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_name = &peer;
        hdr.msg_namelen = sizeof(peer);

        size_t count = 0;
        do
        {
            int nbytes;
            do
            {
                nbytes = recvmsg(sock_, &hdr, 0);
            } while (nbytes == -1 && errno == EINTR);

            if (nbytes < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return io_result{};
                return io_result{errno};
            }

            process_packet(bstring_view{data.data(), static_cast<size_t>(nbytes)}, hdr);

            count++;

        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};
#endif
    }

    // We support different compilation modes for trying different methods of UDP sending by setting
    // these defines; these shouldn't be set directly but rather through the cmake -DLIBQUIC_SEND
    // option.  At most one of these may be defined.
    //
    // OXEN_LIBQUIC_UDP_GSO -- use sendmmsg and GSO to batch-send packets.  Only works on
    // Linux.
    // CMake option: -DLIBQUIC_SEND=gso
    //
    // OXEN_LIBQUIC_UDP_SENDMMSG -- use sendmmsg (but not GSO) to batch-send packets.  Only works on
    // Linux and FreeBSD.
    // CMake option: -DLIBQUIC_SEND=sendmmsg
    //
    // If neither is defined we use plain sendmsg in a loop.

#if (defined(OXEN_LIBQUIC_UDP_GSO) + defined(OXEN_LIBQUIC_UDP_SENDMMSG)) > 1
#error Only one of OXEN_LIBQUIC_UDP_GSO and OXEN_LIBQUIC_UDP_SENDMMSG may be set at once
#endif

    std::pair<io_result, size_t> UDPSocket::send(
            const Address& dest, const std::byte* buf, const size_t* bufsize, uint8_t ecn, size_t n_pkts)
    {

        auto* next_buf = const_cast<char*>(reinterpret_cast<const char*>(buf));
        int rv;
        size_t sent = 0;
        sockaddr* dest_sa = const_cast<Address&>(dest);

        if (ecn != ecn_)
        {
            ecn_ = ecn;
            set_ecn();
        }

#ifdef OXEN_LIBQUIC_UDP_GSO

        // With GSO, we use *one* sendmmsg call which can contain multiple batches of packets; each
        // batch is of size n, where each of the n have the same size.
        //
        // We could have up to the full MAX_BATCH, with the worst case being every packet being a
        // different size than the one before it.
        std::array<std::array<char, CMSG_SPACE(sizeof(uint16_t))>, DATAGRAM_BATCH_SIZE> controls{};
        std::array<uint16_t, MAX_BATCH> gso_sizes{};   // Size of each of the packets
        std::array<uint16_t, MAX_BATCH> gso_counts{};  // Number of packets

        std::array<mmsghdr, MAX_BATCH> msgs{};
        std::array<iovec, MAX_BATCH> iovs{};

        unsigned int msg_count = 0;
        for (size_t i = 0; i < n_pkts; i++)
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
            hdr.msg_name = dest_sa;
            hdr.msg_namelen = dest.socklen();
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
            rv = sendmmsg(sock_, msgs.data(), msg_count, 0);
        } while (rv == -1 && errno == EINTR);

        // Figure out number of packets we actually sent:
        // rv is the number of `msgs` elements that were updated; within each, the `.msg_len` field
        // has been updated to the number of bytes that were sent (which we need to use to figure
        // out how many actual batched packets went out from our batch-of-batches).
#ifndef NDEBUG
        bool found_unsent = false;
#endif
        if (rv >= 0)
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

#elif defined(OXEN_LIBQUIC_UDP_SENDMMSG)  // sendmmsg, but not GSO

        std::array<mmsghdr, MAX_BATCH> msgs{};
        std::array<iovec, MAX_BATCH> iovs{};

        for (size_t i = 0; i < n_pkts; i++)
        {
            assert(bufsize[i] > 0);

            iovs[i].iov_base = next_buf;
            iovs[i].iov_len = bufsize[i];
            next_buf += bufsize[i];

            auto& hdr = msgs[i].msg_hdr;
            hdr.msg_iov = &iovs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_name = dest_sa;
            hdr.msg_namelen = dest.socklen();
        }

        do
        {
            rv = sendmmsg(sock_, msgs.data(), n_pkts, MSG_DONTWAIT);
        } while (rv == -1 && errno == EINTR);

        sent = rv >= 0 ? rv : 0;

#else  // No sendmmsg at all, so we just use sendmsg in a loop
        msghdr hdr{};
        iovec iov;
        hdr.msg_iov = &iov;
        hdr.msg_name = dest_sa;
        hdr.msg_namelen = dest.socklen();

        for (int i = 0; i < n_pkts; ++i)
        {
            assert(bufsize[i] > 0);
            iov.iov_base = next_buf;
            iov.iov_len = bufsize[i];
            next_buf += bufsize[i];

            rv = sendmsg(sock_, &hdr, 0);
            assert(rv == bufsize[i] || rv < 0);
            if (rv < 0)
                break;

            sent++;
        }
#endif

        return {io_result{rv < 0 ? errno : 0}, sent};
    }

#else

    static_assert(std::is_same_v<UDPSocket::socket_t, SOCKET>);

#endif

    void UDPSocket::when_writeable(std::function<void()> cb)
    {
        writeable_callbacks_.push_back(std::move(cb));
        event_add(wev_.get(), nullptr);
    }

}  // namespace oxen::quic
