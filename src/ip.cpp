#include "ip.hpp"

#include "internal.hpp"

namespace oxen::quic
{
    ipv4::ipv4(const std::string& ip)
    {
        if (ip.empty() || ip.find(':') != std::string::npos)
            throw std::invalid_argument{"Cannot parse invalid ipv4 address!"};

        auto rv = inet_pton(AF_INET, ip.c_str(), &addr);

        if (rv < 0)
            throw std::invalid_argument{"System error (ec:{}): {}"_format(errno, std::system_category().message(errno))};

        if (rv == 0)
            throw std::invalid_argument{"IPv4 constructor failed to parse input: {}"_format(ip)};
    }

    const std::string ipv4::to_string() const
    {
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));

        return "{}"_format(buf);
    }

    ipv6::ipv6(const std::string& ip)
    {
        if (ip.empty())
            throw std::invalid_argument{"Cannot parse invalid ipv6 address!"};

        std::array<uint64_t, 2> buf{};
        auto rv = inet_pton(AF_INET6, ip.c_str(), &buf);

        hi = oxenc::big_to_host<uint64_t>(buf[0]);
        lo = oxenc::big_to_host<uint64_t>(buf[1]);

        if (rv < 0)
            throw std::invalid_argument{"System error (ec:{}): {}"_format(errno, std::system_category().message(errno))};

        if (rv == 0)
            throw std::invalid_argument{"IPv4 constructor failed to parse input: {}"_format(ip)};
    }

    in6_addr ipv6::to_in6() const
    {
        in6_addr ret;

        oxenc::write_host_as_big(hi, &ret.s6_addr[0]);
        oxenc::write_host_as_big(lo, &ret.s6_addr[8]);

        return ret;
    }

    const std::string ipv6::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};

        std::array<uint8_t, 16> addr;
        oxenc::write_host_as_big(hi, &addr[0]);
        oxenc::write_host_as_big(lo, &addr[8]);

        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));

        return "{}"_format(buf);
    }

}  //  namespace oxen::quic
