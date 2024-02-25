#include "ip.hpp"

#include "format.hpp"

namespace oxen::quic
{
    ipv4::ipv4(const std::string& ip)
    {
        if (ip.empty() || ip.find(':') != std::string::npos)
            throw std::invalid_argument{"Cannot parse invalid ipv4 address!"};

        char buf[INET_ADDRSTRLEN] = {};
        auto rv = inet_pton(AF_INET, ip.c_str(), buf);

        if (rv < 0)
            throw std::invalid_argument{"System error (ec:{}): {}"_format(errno, std::system_category().message(errno))};

        if (rv == 0)
            throw std::invalid_argument{"IPv4 constructor failed to parse input: {}"_format(ip)};

        addr = oxenc::load_host_to_big<uint32_t>(buf);
    }

    const std::string ipv4::to_string() const
    {
        char buf[INET_ADDRSTRLEN] = {};

        auto bigly = oxenc::host_to_big<uint32_t>(addr);
        inet_ntop(AF_INET, &bigly, buf, sizeof(buf));

        return "{}"_format(buf);
    }
}  //  namespace oxen::quic
