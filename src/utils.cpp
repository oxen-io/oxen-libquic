#include "utils.hpp"

#include <netinet/in.h>
#include <string>


namespace oxen::quic
{
    uint64_t
    get_timestamp()
    {
        struct timespec tp;

        if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) 
        {
            fprintf(stderr, "clock_gettime: %s\n", ngtcp2_strerror(errno));
            exit(EXIT_FAILURE);
        }

        return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
    }

    std::string
    str_tolower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        return s;
    }

    std::mt19937 make_mt19937()
    {
        std::random_device rd;
        return std::mt19937(rd());
    }


    ConnectionID::ConnectionID(const uint8_t* cid, size_t length)
    {
        assert(length <= NGTCP2_MAX_CIDLEN);
        datalen = length;
        std::memmove(data, cid, datalen);
    }


    ConnectionID
    ConnectionID::random(size_t size)
    {
        ConnectionID cid;
        cid.datalen = std::min(size, static_cast<size_t>(NGTCP2_MAX_CIDLEN));
        std::generate(cid.data, (cid.data + cid.datalen), rand);
        return cid;
    }


    Address::Address(std::string addr, uint16_t port) : uvw::Addr{addr, port}
    {
        string_addr = std::string{addr + static_cast<char>(port)};
        memset(&_sock_addr, 0, sizeof(_sock_addr));
        _sock_addr.sin_family = AF_INET;
        _sock_addr.sin_port = htons(port);

        std::cout << "Constructing address..." << std::endl;
        std::cout << "Before:\n\tAddress: " << addr << std::endl;
        std::cout << "\tPort: " << port << "\n" << std::endl;

        if (auto rv = inet_pton(AF_INET, addr.c_str(), &_sock_addr.sin_addr); rv != 1)
            throw std::runtime_error("Error: could not parse IPv4 address from string");

        std::cout << "After:\n\tAddress: " << _sock_addr.sin_addr.s_addr << std::endl;
        std::cout << "\tPort: " << _sock_addr.sin_port << std::endl;
        
        _addr = ngtcp2_addr{reinterpret_cast<sockaddr*>(&_sock_addr), sizeof(_sock_addr)};
    }

}   // namespace oxen::quic



/*
    - Keep in host order, convert to network order only when needed
        - Could also store inside Address as host order, then construct sockaddr when needed
    
    - Implementation should be agnostic to tcp vs udp

    - Tunnel is more like "manager" or "handler"

    - Could have connection/stream manager with multiple connections
        - some are TCP, some are plain streams for IP transmission
    
    - get ngtcp2 debug printing working

*/
