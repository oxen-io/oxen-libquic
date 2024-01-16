#include "address.hpp"

#include <oxenc/endian.h>

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
        }
        // else if (addr.addrlen == sizeof(sockaddr_in))
        else if (addr.addr->sa_family == AF_INET)
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
            auto& nin = reinterpret_cast<const sockaddr_in&>(addr);
            sin.sin_addr = nin.sin_addr;
            sin.sin_port = nin.sin_port;
        }
        else
            throw std::invalid_argument{"What on earth did you pass to this constructor?"};
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

    namespace
    {
        struct ipv4
        {
            uint32_t addr;
            constexpr ipv4(uint32_t a) : addr{a} {}
            constexpr ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) :
                    ipv4{uint32_t{a} << 24 | uint32_t{b} << 16 | uint32_t{c} << 8 | uint32_t{d}}
            {}

            constexpr bool operator==(const ipv4& a) const { return addr == a.addr; }

            constexpr ipv4 to_base(uint8_t mask) const
            {
                return mask < 32 ? ipv4{(addr >> (32 - mask)) << (32 - mask)} : *this;
            }
        };

        struct ipv4_net
        {
            ipv4 base;
            uint8_t mask;

            constexpr bool contains(const ipv4& addr) const { return addr.to_base(mask) == base; }
        };

        constexpr ipv4_net operator/(const ipv4& a, uint8_t mask)
        {
            return ipv4_net{a.to_base(mask), mask};
        }

        static_assert((ipv4(10, 0, 0, 0) / 8).contains(ipv4(10, 0, 0, 0)));
        static_assert((ipv4(10, 0, 0, 0) / 8).contains(ipv4(10, 255, 255, 255)));
        static_assert((ipv4(10, 123, 45, 67) / 8).contains(ipv4(10, 123, 123, 123)));
        static_assert((ipv4(10, 255, 255, 255) / 8).contains(ipv4(10, 0, 0, 0)));
        static_assert((ipv4(10, 255, 255, 255) / 8).contains(ipv4(10, 123, 123, 123)));
        static_assert(not(ipv4(10, 0, 0, 0) / 8).contains(ipv4(11, 0, 0, 0)));
        static_assert(not(ipv4(10, 0, 0, 0) / 8).contains(ipv4(9, 255, 255, 255)));

        struct ipv6
        {
            uint64_t hi, lo;
            ipv6(const unsigned char* addr) :
                    hi{oxenc::load_big_to_host<uint64_t>(addr)}, lo{oxenc::load_big_to_host<uint64_t>(addr + 8)}
            {}
            constexpr ipv6(
                    uint16_t a = 0x0000,
                    uint16_t b = 0x0000,
                    uint16_t c = 0x0000,
                    uint16_t d = 0x0000,
                    uint16_t e = 0x0000,
                    uint16_t f = 0x0000,
                    uint16_t g = 0x0000,
                    uint16_t h = 0x0000) :
                    hi{uint64_t{a} << 48 | uint64_t{b} << 32 | uint64_t{c} << 16 | uint64_t{d}},
                    lo{uint64_t{e} << 48 | uint64_t{f} << 32 | uint64_t{g} << 16 | uint64_t{h}}
            {}

            constexpr bool operator==(const ipv6& a) const { return hi == a.hi && lo == a.lo; }

            constexpr ipv6 to_base(uint8_t mask) const
            {
                ipv6 b;
                if (mask >= 64)
                {
                    b.hi = hi;
                    b.lo = mask < 128 ? (lo >> (128 - mask)) << (128 - mask) : lo;
                }
                else
                {
                    b.hi = (hi >> (64 - mask)) << (64 - mask);
                }
                return b;
            }
        };

        struct ipv6_net
        {
            ipv6 base;
            uint8_t mask;

            constexpr bool contains(const ipv6& addr) const { return addr.to_base(mask) == base; }
        };

        constexpr ipv6_net operator/(const ipv6 a, uint8_t mask)
        {
            return {a.to_base(mask), mask};
        }

        static_assert((ipv6(0x2001, 0xdb8) / 32).contains(ipv6(0x2001, 0xdb8)));
        static_assert((ipv6(0x2001, 0xdb8) / 32).contains(ipv6(0x2001, 0xdb8, 0xffff, 0xffff)));
        static_assert((ipv6(0x2001, 0xdb8, 0xffff) / 32).contains(ipv6(0x2001, 0xdb8)));
        static_assert((ipv6(0x2001, 0xdb8, 0xffff) / 32).contains(ipv6(0x2001, 0xdb8)));

        constexpr ipv4_net ipv4_loopback = ipv4(127, 0, 0, 1) / 8;
        constexpr ipv6 ipv6_loopback(0, 0, 0, 0, 0, 0, 0, 1);

        const std::array ipv4_nonpublic = {
                ipv4(0, 0, 0, 0) / 8,        // Special purpose for current/local/this network
                ipv4(10, 0, 0, 0) / 8,       // Private range
                ipv4(100, 64, 0, 0) / 10,    // Carrier grade NAT private range
                ipv4_loopback,               // Loopback
                ipv4(169, 254, 0, 0) / 16,   // Link-local addresses
                ipv4(172, 16, 0, 0) / 12,    // Private range
                ipv4(192, 0, 0, 0) / 24,     // DS-Lite
                ipv4(192, 0, 2, 0) / 24,     // Test range 1 for docs/examples
                ipv4(192, 88, 99, 0) / 24,   // Reserved; deprecated IPv6-to-IPv4 relay
                ipv4(192, 168, 0, 0) / 16,   // Private range
                ipv4(198, 18, 0, 0) / 15,    // Multi-subnmet benchmark testing range
                ipv4(198, 51, 100, 0) / 24,  // Test range 2 for docs/examples
                ipv4(203, 0, 113, 0) / 24,   // Test range 3 for docs/examples
                ipv4(224, 0, 0, 0) / 4,      // Multicast
                ipv4(240, 0, 0, 0) / 4,      // Multicast
        };

        const std::array ipv6_nonpublic = {
                ipv6() / 128,                      // unspecified addr
                ipv6_loopback / 128,               // loopback
                ipv6(0, 0, 0, 0, 0, 0xffff) / 96,  // IPv4-mapped address
                ipv6(0, 0, 0, 0, 0xffff) / 96,     // IPv4 translated addr
                ipv6(0x64, 0xff9b) / 96,           // IPv4/IPv6 translation
                ipv6(0x64, 0xff9b, 1) / 48,        // IPv4/IPv6 translation
                ipv6(0x100) / 64,                  // Discard
                ipv6(0x200) / 7,                   // Deprecated NSPA-mapped IPv6; Yggdrasil
                ipv6(0x2001, 0x0) / 32,            // Toredo
                ipv6(0x2001, 0x20) / 28,           // ORCHIDv2
                ipv6(0x2001, 0xdb8) / 32,          // Documentation/example
                ipv6(0x2002) / 16,                 // Deprecated 6to4 addressing scheme
                ipv6(0xfc00) / 7,                  // Unique local address
                ipv6(0xfe80) / 10,                 // link-local unicast addressing
                ipv6(0xff00) / 8,                  // Multicast
        };
    }  // namespace

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
