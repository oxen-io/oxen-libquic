#include "ip.hpp"

#include "internal.hpp"

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
}

namespace oxen::quic
{
    ipv4::ipv4(const std::string& str)
    {
        in_addr sin;
        detail::parse_addr(sin, str);
        addr = oxenc::big_to_host(sin.s_addr);
    }

    std::string ipv4::to_string() const
    {
        char buf[INET_ADDRSTRLEN] = {};
        uint32_t net = oxenc::host_to_big(addr);
        inet_ntop(AF_INET, &net, buf, sizeof(buf));

        return "{}"_format(buf);
    }

    std::string detail::masked_ipv4::to_string() const
    {
        return "{}/{}"_format(ip.to_string(), mask);
    }

    std::string detail::masked_ipv6::to_string() const
    {
        return "{}/{}"_format(ip.to_string(), mask);
    }

    in6_addr ipv6::to_in6() const
    {
        in6_addr ret;

        oxenc::write_host_as_big(hi, &ret.s6_addr[0]);
        oxenc::write_host_as_big(lo, &ret.s6_addr[8]);

        return ret;
    }

    ipv6::ipv6(const std::string& str)
    {
        in6_addr sin6;
        detail::parse_addr(sin6, str);

        hi = oxenc::load_big_to_host<uint64_t>(&sin6.s6_addr[0]);
        lo = oxenc::load_big_to_host<uint64_t>(&sin6.s6_addr[8]);
    }

    std::string ipv6::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};

        std::array<uint8_t, 16> addr;

        oxenc::write_host_as_big(hi, &addr[0]);
        oxenc::write_host_as_big(lo, &addr[8]);

        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));

        return "{}"_format(buf);
    }

    namespace detail
    {
        void parse_addr(int af, void* dest, const std::string& from)
        {
            auto rv = inet_pton(af, from.c_str(), dest);

            if (rv == 0)  // inet_pton returns this on invalid input
                throw std::invalid_argument{"Unable to parse IP address!"};
            if (rv < 0)
                throw std::system_error{errno, std::system_category()};
        }

        // Parses an IPv4 address from string
        void parse_addr(in_addr& into, const std::string& from)
        {
            parse_addr(AF_INET, &into.s_addr, from);
        }

        // Parses an IPv6 address from string
        void parse_addr(in6_addr& into, const std::string& from)
        {
            parse_addr(AF_INET6, &into, from);
        }
    }  // namespace detail
}  //  namespace oxen::quic
