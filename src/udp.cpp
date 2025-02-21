
extern "C"
{

#ifdef __linux__
#include <netinet/udp.h>
#endif

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include <fcntl.h>
#include <unistd.h>

#ifndef _WIN32
#include <netinet/ip.h>
#endif
}

#include "internal.hpp"
#include "udp.hpp"

#include <system_error>

#ifdef _WIN32

#define CMSG_FIRSTHDR(h) WSA_CMSG_FIRSTHDR(h)
#define CMSG_NXTHDR(h, c) WSA_CMSG_NXTHDR(h, c)
#define QUIC_CMSG_DATA(c) WSA_CMSG_DATA(c)  // conflicts without the QUIC_ prefix
#define CMSG_SPACE(c) WSA_CMSG_SPACE(c)
#define CMSG_LEN(c) WSA_CMSG_LEN(c)

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#else  // not windows

#define QUIC_CMSG_DATA(c) CMSG_DATA(c)

#endif

namespace oxen::quic
{

#ifdef _WIN32
    static_assert(std::is_same_v<UDPSocket::socket_t, SOCKET>);
    constexpr int QUIC_IPV4_ECN = IP_ECN;
    constexpr int QUIC_IPV6_ECN = IPV6_ECN;
    constexpr uint8_t QUIC_ECN_MASK = 0xff;
#else
    constexpr uint8_t QUIC_ECN_MASK = IPTOS_ECN_MASK;
    constexpr int QUIC_IPV6_ECN = IPV6_TCLASS;
    constexpr int QUIC_IPV4_ECN =
#if defined(__APPLE__)  // Apple got --><-- this close to getting it right but then got it wrong
            IP_RECVTOS;
#else
            IP_TOS;
#endif
#endif

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    static int check_rv(int rv, std::string_view action)
    {
        std::optional<std::error_code> ec;
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            ec.emplace(WSAGetLastError(), std::system_category());
#else
        if (rv == -1)
            ec.emplace(errno, std::system_category());

#endif
        if (ec)
        {
            log::error(log_cat, "Got error {} ({}) during {}", ec->value(), ec->message(), action);
            throw std::system_error{*ec};
        }

        return rv;
    }

    // Same as above, but just logs, doesn't throw.
    static void log_rv_error(int rv, std::string_view action)
    {
        std::optional<std::error_code> ec;
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            ec.emplace(WSAGetLastError(), std::system_category());
#else
        if (rv == -1)
            ec.emplace(errno, std::system_category());

#endif
        if (ec)
            log::error(log_cat, "Got error {} ({}) during {}", ec->value(), ec->message(), action);
    }

#ifdef _WIN32
    std::mutex get_wsa_mutex;
    LPFN_WSASENDMSG WSASendMsg = nullptr;
    LPFN_WSARECVMSG WSARecvMsg = nullptr;

    static void init_wsa_bs()
    {
        std::lock_guard lock{get_wsa_mutex};
        if (!(WSARecvMsg && WSASendMsg))
        {
            GUID recvmsg_guid = WSAID_WSARECVMSG;
            GUID sendmsg_guid = WSAID_WSASENDMSG;
            SOCKET tmpsock = INVALID_SOCKET;
            DWORD nothing = 0;
            tmpsock = socket(AF_INET, SOCK_DGRAM, 0);
            if (auto rv = WSAIoctl(
                        tmpsock,
                        SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &recvmsg_guid,
                        sizeof(recvmsg_guid),
                        &WSARecvMsg,
                        sizeof(WSARecvMsg),
                        &nothing,
                        nullptr,
                        nullptr);
                rv == SOCKET_ERROR)
            {
                log::critical(log_cat, "WSAIoctl magic BS failed to retrieve magic BS recvmsg wannabe function pointer!");
                throw std::runtime_error{"Unable to initialize windows recvmsg function pointer!"};
            }

            if (auto rv = WSAIoctl(
                        tmpsock,
                        SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &sendmsg_guid,
                        sizeof(sendmsg_guid),
                        &WSASendMsg,
                        sizeof(WSASendMsg),
                        &nothing,
                        nullptr,
                        nullptr);
                rv == SOCKET_ERROR)
            {
                log::critical(log_cat, "WSAIoctl magic BS failed to retrieve magic BS sendmsg-wannabe function pointer!");
                throw std::runtime_error{"Unable to initialize windows sendmsg function pointer!"};
            }
        }
    }
#endif

    UDPSocket::UDPSocket(event_base* ev_loop, const Address& addr, receive_callback_t on_receive) :
            ev_{ev_loop}, receive_callback_{std::move(on_receive)}
    {
        assert(ev_);

        if (!receive_callback_)
            throw std::logic_error{"UDPSocket construction requires a non-empty receive callback"};

        const int sockopt_proto = addr.is_ipv6() ? IPPROTO_IPV6 : IPPROTO_IP;
        const unsigned int sockopt_on = 1;
        const unsigned int sockopt_off = 0;
        const size_t sockopt_onoff_size = sizeof(sockopt_on);
#ifdef _WIN32
        const auto* sockopt_on_ptr = (const char*)&sockopt_on;
        const auto* sockopt_off_ptr = (const char*)&sockopt_off;
#else
        const auto* sockopt_on_ptr = &sockopt_on;
        const auto* sockopt_off_ptr = &sockopt_off;
#endif

#ifdef _WIN32
        init_wsa_bs();
#endif

        sock_ = check_rv(socket(addr.is_ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM, 0), "socket creation");

        // Enable dual stack mode if appropriate:
        if (addr.is_ipv6())
        {
            const auto* v6only = addr.dual_stack ? sockopt_off_ptr : sockopt_on_ptr;
            check_rv(setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY, v6only, sockopt_onoff_size), "setting v6only flag");
        }

        // Enable ECN notification on packets we receive:
#ifndef _WIN32
        check_rv(
                setsockopt(
                        sock_,
                        sockopt_proto,
                        addr.is_ipv6() ? IPV6_RECVTCLASS : IP_RECVTOS,
                        &sockopt_on,
                        sizeof(sockopt_on)),
                "enable ecn");
#else
        // Not supported before Windows 11 (and not in mingw)
        // check_rv(WSASetRecvIPEcn(sock_, 1), "enable ecn");
#endif

#ifdef __APPLE__
        // As usual, macOS is a pile of garbage: it is completely broken when trying to get pktinfo
        // on a dual-stack socket: instead of giving us useful packet info, it either gives us
        // invalid garbage that changes on every packet, or else just doesn't give us anything at
        // all.  Thus we turn this on only for IPv4 sockets; expect proper working OS APIs on macOS
        // is apparently a "you're holding it wrong" problem, so to hell with it: if you're a user
        // and you want it to work you need to upgrade (i.e. switch) to an OS made by someone who
        // realizes that making an OS involves more than deciding on right shade of lipstick to
        // apply to a pig.
        const bool broken_os = addr.is_ipv6();
#else
        constexpr bool broken_os = false;
#endif

        // Enable destination address info in the packet info:
        if (!broken_os)
        {
            check_rv(
                    setsockopt(
                            sock_,
                            sockopt_proto,
                            addr.is_ipv6() ? IPV6_RECVPKTINFO :
#if defined(IP_RECVDSTADDR) && !defined(_WIN32)
                                           IP_RECVDSTADDR,
#else
                                           IP_PKTINFO,
#endif
                            sockopt_on_ptr,
                            sockopt_onoff_size),
                    "enable dest addr info");

#ifdef _WIN32
            // On windows dual stack sockets we have to set IP_PKTINFO in addition to IPV6_PKTINFO
            // to ensure we get dest addr for IPv4-mapped-IPv6 addresses.  (Don't do this under
            // wine, though, because it completely breaks the socket under wine.)
            if (!EMULATING_HELL && addr.is_ipv6() && addr.dual_stack)
                check_rv(
                        setsockopt(sock_, IPPROTO_IP, IP_PKTINFO, sockopt_on_ptr, sockopt_onoff_size),
                        "enable ipv4 dest addr info");
#endif
        }

        // Bind!
        check_rv(bind(sock_, addr, addr.socklen()), "bind");
        check_rv(getsockname(sock_, bound_, bound_.socklen_ptr()), "getsockname");

        // Make the socket non-blocking:
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock_, FIONBIO, &mode);
#else
        check_rv(fcntl(sock_, F_SETFL, O_NONBLOCK), "set non-blocking");
#endif

        rev_.reset(event_new(
                ev_,
                sock_,
                EV_READ | EV_PERSIST,
                [](evutil_socket_t, short, void* self) {
#ifndef NDEBUG
                    log_rv_error(
#endif
                            static_cast<UDPSocket*>(self)
                                    ->receive()
#ifndef NDEBUG
                                    .error_code,
                            "udp::receive()")
#endif
                            ;
                },
                this));
        event_add(rev_.get(), nullptr);

        wev_.reset(event_new(
                ev_,
                sock_,
                EV_WRITE,
                [](evutil_socket_t, short, void* self_) {
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
#ifdef _WIN32
        ::closesocket(sock_);
#else
        ::close(sock_);
#endif
    }

    void UDPSocket::process_packet(bspan payload, msghdr& hdr)
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
        if (MSG_TRUNC &
#ifdef _WIN32
            hdr.dwFlags
#else
            hdr.msg_flags
#endif
        )
        {
            log::warning(log_cat, "Dropping truncated UDP packet");
            return;
        }

        receive_callback_(Packet{bound_, payload, hdr});
    }

    union alignas(cmsghdr) recv_cmsg_data
    {
        char ecn[CMSG_SPACE(sizeof(int))];  // a char most places but an int on windows because yay
        char pktinfo4[CMSG_SPACE(sizeof(in_pktinfo))];
        char pktinfo6[CMSG_SPACE(sizeof(in6_pktinfo))];
    };

    io_result UDPSocket::receive()
    {
#ifdef OXEN_LIBQUIC_RECVMMSG
        std::array<sockaddr_in6, DATAGRAM_BATCH_SIZE> peers;
        std::array<iovec, DATAGRAM_BATCH_SIZE> iovs;
        std::array<mmsghdr, DATAGRAM_BATCH_SIZE> msgs = {};
        std::array<recv_cmsg_data, DATAGRAM_BATCH_SIZE> cmsgs = {};

        std::array<std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD>, DATAGRAM_BATCH_SIZE> data;

        for (size_t i = 0; i < DATAGRAM_BATCH_SIZE; i++)
        {
            iovs[i].iov_base = data[i].data();
            iovs[i].iov_len = data[i].size();
            auto& h = msgs[i].msg_hdr;
            h.msg_iov = &iovs[i];
            h.msg_iovlen = 1;
            h.msg_name = &peers[i];
            h.msg_namelen = sizeof(peers[i]);
            h.msg_control = &cmsgs[i];
            h.msg_controllen = sizeof(cmsgs[i]);
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
                process_packet(bspan{data[i].data(), msgs[i].msg_len}, msgs[i].msg_hdr);

            count += nread;

            if (nread < static_cast<int>(DATAGRAM_BATCH_SIZE))
                // We didn't fill the recvmmsg array so must be done
                return io_result{};

        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};

#else  // no recvmmsg

        sockaddr_storage peer{};
        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD> data;

        recv_cmsg_data cmsg{};

#ifdef _WIN32
        // Microsoft renames everything but uses the same structure just to be obtuse:
        WSABUF iov;
        iov.buf = reinterpret_cast<char*>(data.data());
        iov.len = data.size();
        WSAMSG hdr{};
        hdr.lpBuffers = &iov;
        hdr.dwBufferCount = 1;
        hdr.name = reinterpret_cast<sockaddr*>(&peer);
        hdr.namelen = sizeof(peer);
        hdr.Control.buf = (char*)&cmsg;
        hdr.Control.len = sizeof(cmsg);
#else
        iovec iov;
        iov.iov_base = data.data();
        iov.iov_len = data.size();
        msghdr hdr{};
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_name = &peer;
        hdr.msg_namelen = sizeof(peer);
        hdr.msg_control = &cmsg;
        hdr.msg_controllen = sizeof(cmsg);
#endif

        size_t count = 0;
        do
        {
#ifdef _WIN32
            DWORD nbytes;
            auto rv = WSARecvMsg(sock_, &hdr, &nbytes, nullptr, nullptr);
            if (rv == SOCKET_ERROR)
            {
                auto error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK)
                    return io_result{};
                return io_result::wsa(error);
            }
#else
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
#endif

            process_packet(bspan{data.data(), static_cast<size_t>(nbytes)}, hdr);

            count++;

        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};
#endif
    }

    template <typename CM>
    static size_t set_ecn_cmsg(CM* cm, const int ecn, const bool ipv4)
    {
        if (ipv4)
        {
            cm->cmsg_level = IPPROTO_IP;
#ifdef _WIN32
            cm->cmsg_type = IP_ECN;
#else
            cm->cmsg_type = IP_TOS;
#endif
        }
        else
        {
            cm->cmsg_level = IPPROTO_IPV6;
#ifdef _WIN32
            cm->cmsg_type = IPV6_ECN;
#else
            cm->cmsg_type = IPV6_TCLASS;
#endif
        }
        cm->cmsg_len = CMSG_LEN(sizeof(ecn));
        std::memcpy(QUIC_CMSG_DATA(cm), &ecn, sizeof(ecn));
        return CMSG_SPACE(sizeof(ecn));
    }

    // We support different compilation modes for trying different methods of UDP sending by setting
    // these defines; these shouldn't be set directly but rather through the cmake -DLIBQUIC_SEND
    // option.  At most one of these may be defined.
    //
    // OXEN_LIBQUIC_UDP_GSO -- use sendmmsg and GSO to batch-send packets.  Only works on
    // Linux.  Will fall back to SENDMMSG if the required UDP_SEGMENT is not defined (i.e. on older
    // Linux distros).
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

#if defined(OXEN_LIBQUIC_UDP_GSO) && !defined(UDP_SEGMENT)
#undef OXEN_LIBQUIC_UDP_GSO
#define OXEN_LIBQUIC_UDP_SENDMMSG
#endif

    std::pair<io_result, size_t> UDPSocket::send(
            const Path& path, const std::byte* buf, const size_t* bufsize, uint8_t ecn, size_t n_pkts)
    {
        auto* next_buf = const_cast<char*>(reinterpret_cast<const char*>(buf));
        int rv = 0;
        size_t sent = 0;

        const bool set_source_addr = bound_.is_any_addr() && !path.local.is_any_addr();

#ifdef _WIN32
        // On Windows, when using a dual-stack socket, IPv4 destinations must always be
        // passed as IPv4-mapped-IPv6
        std::optional<Address> mapped_remote;
        if (bound_.is_ipv6() && path.remote.is_ipv4())
            mapped_remote = path.remote.mapped_ipv4_as_ipv6();
        const auto& remote = mapped_remote ? *mapped_remote : path.remote;
#else
        const auto& remote = path.remote;
#endif

        sockaddr* dest_sa = const_cast<Address&>(remote);

        const bool source_ipv4 = path.local.is_ipv4();
        union
        {
            in_pktinfo v4;
            in6_pktinfo v6;
        } source_addr;
        const size_t source_addrlen = source_ipv4 ? sizeof(in_pktinfo) : sizeof(in6_pktinfo);
        const int source_cmsg_level = source_ipv4 ? IPPROTO_IP : IPPROTO_IPV6;
        const int source_cmsg_type = source_ipv4 ? IP_PKTINFO : IPV6_PKTINFO;
        if (set_source_addr)
        {
            std::memset(&source_addr, 0, sizeof(source_addr));
            if (source_ipv4)
#ifdef _WIN32
                source_addr.v4.ipi_addr
#else
                source_addr.v4.ipi_spec_dst
#endif
                        = path.local.in4().sin_addr;
            else
                source_addr.v6.ipi6_addr = path.local.in6().sin6_addr;
        }

#ifdef OXEN_LIBQUIC_UDP_GSO

        // With GSO, we use *one* sendmmsg call which can contain multiple batches of packets; each
        // batch is of size n, where each of the n have the same size.
        //
        // We could have up to the full MAX_BATCH, with the worst case being every packet being a
        // different size than the one before it.
        alignas(cmsghdr) std::array<
                std::array<char, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(in6_pktinfo))>,
                DATAGRAM_BATCH_SIZE>
                controls{};
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
            auto& control = controls[msg_count];
            iov.iov_base = next_buf;
            iov.iov_len = gso_count * gso_size;
            next_buf += iov.iov_len;
            msg_count++;
            auto& hdr = msg.msg_hdr;
            hdr.msg_iov = &iov;
            hdr.msg_iovlen = 1;
            hdr.msg_name = dest_sa;
            hdr.msg_namelen = remote.socklen();
            hdr.msg_control = control.data();
            hdr.msg_controllen = control.size();

            auto* cm = CMSG_FIRSTHDR(&hdr);
            size_t actual_size = set_ecn_cmsg(cm, ecn, source_ipv4);

            if (set_source_addr)
            {
                cm = CMSG_NXTHDR(&hdr, cm);
                cm->cmsg_level = source_cmsg_level;
                cm->cmsg_type = source_cmsg_type;
                cm->cmsg_len = CMSG_LEN(source_addrlen);
                std::memcpy(CMSG_DATA(cm), &source_addr, source_addrlen);
                actual_size += CMSG_SPACE(source_addrlen);
            }

            if (gso_count > 1)
            {
                cm = CMSG_NXTHDR(&hdr, cm);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type = UDP_SEGMENT;
                cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                actual_size += CMSG_SPACE(sizeof(uint16_t));
                *reinterpret_cast<uint16_t*>(QUIC_CMSG_DATA(cm)) = gso_size;
            }
            hdr.msg_controllen = actual_size;
        }

        do
        {
            rv = sendmmsg(sock_, msgs.data(), msg_count, 0);
            log::trace(log_cat, "sendmmsg returned {}", rv);
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

        alignas(cmsghdr) std::array<std::array<char, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(in6_pktinfo))>, MAX_BATCH>
                controls{};

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
            hdr.msg_namelen = remote.socklen();

            auto& control = controls[i];
            hdr.msg_control = control.data();
            hdr.msg_controllen = control.size();

            auto* cm = CMSG_FIRSTHDR(&hdr);
            size_t actual_size = set_ecn_cmsg(cm, ecn, source_ipv4);

            if (set_source_addr)
            {
                cm = CMSG_NXTHDR(&hdr, cm);
                cm->cmsg_level = source_cmsg_level;
                cm->cmsg_type = source_cmsg_type;
                cm->cmsg_len = CMSG_LEN(source_addrlen);
                std::memcpy(CMSG_DATA(cm), &source_addr, source_addrlen);
                actual_size += CMSG_SPACE(source_addrlen);
            }
            hdr.msg_controllen = actual_size;
        }

        do
        {
            rv = sendmmsg(sock_, msgs.data(), n_pkts, MSG_DONTWAIT);
        } while (rv == -1 && errno == EINTR);

        sent = rv >= 0 ? rv : 0;

#else  // No sendmmsg at all, so we just use sendmsg in a loop

#ifdef _WIN32
        // Microsoft renames everything but uses the same structure just to be obtuse:
        WSAMSG hdr{};
        WSABUF iov;
        hdr.lpBuffers = &iov;
        hdr.dwBufferCount = 1;
        hdr.name = dest_sa;
        hdr.namelen = remote.socklen();
#else
        msghdr hdr{};
        iovec iov;
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_name = dest_sa;
        hdr.msg_namelen = remote.socklen();
#endif
        alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(in6_pktinfo))> control{};
#ifdef _WIN32
        hdr.Control.buf = control.data();
        auto& hdr_msg_controllen = hdr.Control.len;
#else
        hdr.msg_control = control.data();
        auto& hdr_msg_controllen = hdr.msg_controllen;
#endif
        hdr_msg_controllen = control.size();

        auto* cm = CMSG_FIRSTHDR(&hdr);

        size_t actual_size = set_ecn_cmsg(cm, ecn, remote.is_ipv4() || remote.is_ipv4_mapped_ipv6());

        if (set_source_addr)
        {
            cm = CMSG_NXTHDR(&hdr, cm);
            cm->cmsg_level = source_cmsg_level;
            cm->cmsg_type = source_cmsg_type;
            cm->cmsg_len = CMSG_LEN(source_addrlen);
            std::memcpy(QUIC_CMSG_DATA(cm), &source_addr, source_addrlen);
            actual_size += CMSG_SPACE(source_addrlen);
        }

        hdr_msg_controllen = actual_size;

        for (size_t i = 0; i < n_pkts; ++i)
        {
            assert(bufsize[i] > 0);
#ifdef _WIN32
            iov.buf = next_buf;
            iov.len = bufsize[i];
            next_buf += bufsize[i];

            DWORD bytes_sent;
            rv = WSASendMsg(sock_, &hdr, 0, &bytes_sent, nullptr, nullptr);
            if (rv == SOCKET_ERROR)
                return {io_result::wsa(WSAGetLastError()), sent};
            assert(bytes_sent == bufsize[i]);

#else
            iov.iov_base = next_buf;
            iov.iov_len = bufsize[i];
            next_buf += bufsize[i];

            rv = sendmsg(sock_, &hdr, 0);
            if (rv < 0)
                break;
            assert(static_cast<size_t>(rv) == bufsize[i]);
#endif

            sent++;
        }
#endif

        return {io_result{rv < 0 ? errno : 0}, sent};
    }

    void UDPSocket::when_writeable(std::function<void()> cb)
    {
        writeable_callbacks_.push_back(std::move(cb));
        event_add(wev_.get(), nullptr);
    }

    Packet::Packet(const Address& local, bspan data, msghdr& hdr) :
            path{local,
#ifdef _WIN32
                 {static_cast<const sockaddr*>(hdr.name), hdr.namelen}
#else
                 {static_cast<const sockaddr*>(hdr.msg_name), hdr.msg_namelen}
#endif
            },
            pkt_data{data}
    {
        assert(path.remote.is_ipv4() || path.remote.is_ipv6());

        for (auto cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg))
        {
            if (cmsg->cmsg_len == 0)
                continue;

            if (cmsg->cmsg_level == IPPROTO_IP)
            {
                if (cmsg->cmsg_type == QUIC_IPV4_ECN)
                    pkt_info.ecn = *reinterpret_cast<uint8_t*>(QUIC_CMSG_DATA(cmsg)) & QUIC_ECN_MASK;

#if defined(IP_RECVDSTADDR) && !defined(_WIN32)
                if (cmsg->cmsg_type == IP_RECVDSTADDR)
                    path.local.set_addr(reinterpret_cast<const struct in_addr*>(QUIC_CMSG_DATA(cmsg)));
#else
                if (cmsg->cmsg_type == IP_PKTINFO)
                    path.local.set_addr(&reinterpret_cast<const struct in_pktinfo*>(QUIC_CMSG_DATA(cmsg))->ipi_addr);
#endif
            }
            else if (cmsg->cmsg_level == IPPROTO_IPV6)
            {
                if (cmsg->cmsg_type == QUIC_IPV6_ECN)
                {
                    int tclass;
                    std::memcpy(&tclass, QUIC_CMSG_DATA(cmsg), sizeof(int));
                    pkt_info.ecn = static_cast<uint8_t>(tclass & QUIC_ECN_MASK);
                }

                if (cmsg->cmsg_type == IPV6_PKTINFO)
                    path.local.set_addr(&reinterpret_cast<const struct in6_pktinfo*>(QUIC_CMSG_DATA(cmsg))->ipi6_addr);
            }
        }
        log::trace(log_cat, "incoming packet path is {}", path);
    }

    void Packet::ensure_owned_data()
    {
        if (auto* data_sp = std::get_if<bspan>(&pkt_data))
            pkt_data = std::vector(data_sp->begin(), data_sp->end());
    }

}  // namespace oxen::quic
