#include "utils.hpp"
#include "connection.hpp"

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


    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref *conn_ref) 
    {
        Connection *c = reinterpret_cast<Connection*>(conn_ref->user_data);
        return c->conn.get();
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
        string_addr = addr + ":"s + std::to_string(port);

        memset(&_sock_addr, 0, sizeof(_sock_addr));
        _sock_addr.sin_family = AF_INET;
        _sock_addr.sin_port = htons(port);

        // std::cout << "Constructing address..." << std::endl;
        // std::cout << "Before:\n\tAddress: " << addr << std::endl;
        // std::cout << "\tPort: " << port << "\n" << std::endl;

        if (auto rv = inet_pton(AF_INET, addr.c_str(), &_sock_addr.sin_addr); rv != 1)
            throw std::runtime_error("Error: could not parse IPv4 address from string");

        // std::cout << "After:\n\tAddress: " << _sock_addr.sin_addr.s_addr << std::endl;
        // std::cout << "\tPort: " << _sock_addr.sin_port << std::endl;
    }

}   // namespace oxen::quic
