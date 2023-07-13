#include "address.hpp"

namespace oxen::quic
{
    Address::Address(const std::string& addr, uint16_t port)
    {
        if (addr.empty())
        {
            // Default to all-0 IPv6 address, which is good (it's `::`, the IPv6 any addr)
            reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_port = oxenc::host_to_big(port);
        }
        int rv;
        if (addr.find(':') != std::string_view::npos)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            sin6.sin6_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in6);
            rv = inet_pton(AF_INET6, addr.c_str(), &sin6.sin6_addr);
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
            std::system_error{errno, std::system_category()};
    }

    void Address::map_ipv4_as_ipv6()
    {
        const auto& a4 = in4();
        sockaddr_in6 a6{};
        a6.sin6_family = AF_INET6;
        a6.sin6_port = a4.sin_port;
        a6.sin6_addr.s6_addr[10] = 0xff;
        a6.sin6_addr.s6_addr[11] = 0xff;
        std::memcpy(&a6.sin6_addr.s6_addr[12], &a4.sin_addr.s_addr, 4);
        std::memcpy(&_sock_addr, &a6, sizeof(a6));
        update_socklen(sizeof(a6));
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

    std::string Path::to_string() const
    {
        return "{{{} ➙ {}}}"_format(local, remote);
    }

}  // namespace oxen::quic
