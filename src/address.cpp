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
    
}   // namespace oxen::quic
