#include "address.hpp"

#include <oxenc/endian.h>

#include "internal.hpp"

namespace oxen::quic
{
    Address::Address(const std::string& addr, uint16_t port)
    {
        int rv = 1;
        if (addr.empty() || addr.find(':') != std::string_view::npos)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            sin6.sin6_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in6);
            if (!addr.empty())
                rv = inet_pton(AF_INET6, addr.c_str(), &sin6.sin6_addr);
            // Otherwise default to all-0 IPv6 address, which is good (it's `::`, the IPv6 any addr)
        }
        else
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin4 = reinterpret_cast<sockaddr_in&>(_sock_addr);
            sin4.sin_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in);
            rv = inet_pton(AF_INET, addr.c_str(), &sin4.sin_addr);
        }
        if (rv == 0)  // inet_pton returns this on invalid input
            throw std::invalid_argument{"Cannot construct address: invalid IP"};
        if (rv < 0)
            throw std::system_error{errno, std::system_category()};
    }

    Address::Address(const ngtcp2_addr& addr)
    {
        // if (addr.addrlen == sizeof(sockaddr_in6))
        if (addr.addr->sa_family == AF_INET6)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            auto& nin6 = reinterpret_cast<const sockaddr_in6&>(addr);
            sin6.sin6_addr = nin6.sin6_addr;
            sin6.sin6_port = nin6.sin6_port;
            update_socklen(sizeof(sockaddr_in6));
        }
        // else if (addr.addrlen == sizeof(sockaddr_in))
        else if (addr.addr->sa_family == AF_INET)
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
            auto& nin = reinterpret_cast<const sockaddr_in&>(addr);
            sin.sin_addr = nin.sin_addr;
            sin.sin_port = nin.sin_port;
            update_socklen(sizeof(sockaddr_in));
        }
        else
            throw std::invalid_argument{"What on earth did you pass to this constructor?"};
    }

    Address::Address(ipv4 v4, uint16_t port)
    {
        _sock_addr.ss_family = AF_INET;

        auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
        sin.sin_port = oxenc::host_to_big(port);

        auto bigly = oxenc::host_to_big<uint32_t>(v4.addr);
        std::memcpy(&sin.sin_addr, &bigly, sizeof(struct in_addr));

        update_socklen(sizeof(sockaddr_in));
    }

    Address::Address(ipv6 v6, uint16_t port)
    {
        _sock_addr.ss_family = AF_INET6;

        auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
        sin6.sin6_port = oxenc::host_to_big(port);

        auto bigly = oxenc::host_to_big<uint64_t>(v6.hi);
        std::memcpy(&sin6.sin6_addr.s6_addr, &bigly, sizeof(uint64_t));

        update_socklen(sizeof(sockaddr_in6));
    }

    void Address::set_addr(const struct in_addr* addr)
    {
        if (_sock_addr.ss_family == AF_INET6)
        {
            // We're changing from IPv6 to IPv4, so need to preserve the port value:
            auto p = reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_port;
            auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
            sin.sin_family = AF_INET;
            sin.sin_port = p;
            update_socklen(sizeof(sockaddr_in));
        }
        std::memcpy(&reinterpret_cast<sockaddr_in&>(_sock_addr).sin_addr, addr, sizeof(struct in_addr));
    }

    void Address::set_addr(const struct in6_addr* addr)
    {
        if (_sock_addr.ss_family == AF_INET)
        {
            // We're changing from IPv4 to IPv6, so need to preserve the port value and non-address
            // parts of the sockaddr_in6
            auto p = reinterpret_cast<sockaddr_in&>(_sock_addr).sin_port;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            std::memset(&sin6, 0, sizeof(sockaddr_in6));
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = p;
        }
        std::memcpy(&reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_addr, addr, sizeof(struct in6_addr));
    }

    static inline constexpr auto ipv6_ipv4_mapped_prefix = "\0\0\0\0\0\0\0\0\0\0\xff\xff"sv;
    static_assert(ipv6_ipv4_mapped_prefix.size() == 12);

    void Address::map_ipv4_as_ipv6()
    {
        if (!is_ipv4())
            throw std::logic_error{"Address::map_ipv4_as_ipv6 cannot be called on a non-IPv4 address"};
        const auto& a4 = in4();
        sockaddr_in6 a6{};
        a6.sin6_family = AF_INET6;
        a6.sin6_port = a4.sin_port;
        std::memcpy(&a6.sin6_addr.s6_addr[0], ipv6_ipv4_mapped_prefix.data(), 12);
        std::memcpy(&a6.sin6_addr.s6_addr[12], &a4.sin_addr.s_addr, 4);
        std::memcpy(&_sock_addr, &a6, sizeof(a6));
        update_socklen(sizeof(a6));
    }

    bool Address::is_ipv4_mapped_ipv6() const
    {
        return is_ipv6() && std::memcmp(in6().sin6_addr.s6_addr, ipv6_ipv4_mapped_prefix.data(), 12) == 0;
    }

    void Address::unmap_ipv4_from_ipv6()
    {
        if (!is_ipv4_mapped_ipv6())
            throw std::logic_error{"Address::unmap_ipv4_ipv6 cannot be called on a non-IPv4-mapped IPv6 address"};
        const auto& a6 = in6();
        sockaddr_in a4{};
        a4.sin_family = AF_INET;
        a4.sin_port = a6.sin6_port;
        std::memcpy(&a4.sin_addr.s_addr, &a6.sin6_addr.s6_addr[12], 4);
        std::memcpy(&_sock_addr, &a4, sizeof(a4));
        update_socklen(sizeof(a4));
    }

    bool Address::is_public_ip() const
    {
        if (is_any_addr())
            return false;
        if (is_ipv4())
        {
            ipv4 addr{oxenc::big_to_host<uint32_t>(in4().sin_addr.s_addr)};
            for (const auto& range : ipv4_nonpublic)
                if (range.contains(addr))
                    return false;
        }
        else if (is_ipv4_mapped_ipv6())
        {
            return unmapped_ipv4_from_ipv6().is_public();
        }
        else if (is_ipv6())
        {
            ipv6 addr{in6().sin6_addr.s6_addr};
            for (const auto& range : ipv6_nonpublic)
                if (range.contains(addr))
                    return false;
        }
        return true;
    }

    bool Address::is_public() const
    {
        return is_any_port() ? false : is_public_ip();
    }

    bool Address::is_loopback() const
    {
        if (!is_addressable())
            return false;
        if (is_ipv4())
            return ipv4_loopback.contains(ipv4{oxenc::big_to_host<uint32_t>(in4().sin_addr.s_addr)});
        if (is_ipv4_mapped_ipv6())
            return unmapped_ipv4_from_ipv6().is_public();
        if (is_ipv6())
            return ipv6{in6().sin6_addr.s6_addr} == ipv6_loopback;
        return false;
    }

    std::string Address::host() const
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (is_ipv6())
        {
            inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_addr, buf, sizeof(buf));
            return "[{}]:{}"_format(buf, port());
        }
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_addr, buf, sizeof(buf));
        return "{}"_format(buf);
    }

    std::string Address::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (is_ipv6())
        {
            inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_addr, buf, sizeof(buf));
            return "[{}]:{}"_format(buf, port());
        }
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_addr, buf, sizeof(buf));
        return "{}:{}"_format(buf, port());
    }

    void Path::set_new_remote(const ngtcp2_addr& new_remote)
    {
        memcpy(_path.remote.addr, new_remote.addr, new_remote.addrlen);
        _path.remote.addrlen = new_remote.addrlen;
        remote = Address{_path.remote.addr, _path.remote.addrlen};
    }

    std::string Path::to_string() const
    {
        return "{{{} ➙ {}}}"_format(local, remote);
    }

}  // namespace oxen::quic
