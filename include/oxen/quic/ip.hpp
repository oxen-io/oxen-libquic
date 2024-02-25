#pragma once

#include "formattable.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    struct ipv4
    {
        // Held in host order
        uint32_t addr;

        ipv4() = default;
        // Constructor using host order IP address string
        ipv4(const std::string& ip);

        constexpr ipv4(uint32_t a) : addr{a} {}
        constexpr ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) :
                ipv4{uint32_t{a} << 24 | uint32_t{b} << 16 | uint32_t{c} << 8 | uint32_t{d}}
        {}

        const std::string to_string() const;

        const in_addr& to_inaddr() const { return reinterpret_cast<const in_addr&>(addr); }

        explicit operator const uint32_t&() const { return reinterpret_cast<const uint32_t&>(addr); }

        constexpr bool operator==(const ipv4& a) const { return addr == a.addr; }

        constexpr bool operator!=(const ipv4& a) const { return not(*this == a); }

        constexpr bool operator<(const ipv4& a) const { return addr < a.addr; }

        constexpr ipv4 to_base(uint8_t mask) const { return mask < 32 ? ipv4{(addr >> (32 - mask)) << (32 - mask)} : *this; }
    };

    struct ipv4_net
    {
        ipv4 base;
        uint8_t mask;

        const std::string to_string() const { return base.to_base(mask).to_string(); }

        constexpr bool operator==(const ipv4_net& a) const { return base == a.base && mask == a.mask; }

        constexpr bool operator!=(const ipv4_net& a) const { return not(*this == a); }

        constexpr bool operator<(const ipv4_net& a) const { return base.to_base(mask) < a.base.to_base(a.mask); }

        constexpr bool contains(const ipv4& addr) const { return addr.to_base(mask) == base; }
    };

    inline constexpr ipv4_net operator/(const ipv4& a, uint8_t mask)
    {
        return ipv4_net{a.to_base(mask), mask};
    }

    struct ipv6
    {
        // Held in host order
        uint64_t hi, lo;

        // Network order string constructor
        ipv6(const std::string& ip) : ipv6{reinterpret_cast<const unsigned char*>(ip.data())} {}
        // Network order constructor
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

        const std::string to_string() const
        {
            char buf[INET6_ADDRSTRLEN] = {};

            auto bigly = oxenc::host_to_big<uint64_t>(hi);
            inet_ntop(AF_INET6, &bigly, buf, sizeof(buf));

            return "[{}]"_format(buf);
        }

        constexpr bool operator==(const ipv6& a) const { return hi == a.hi && lo == a.lo; }

        constexpr bool operator!=(const ipv6& a) const { return not(*this == a); }

        constexpr bool operator<(const ipv6& a) const { return std::tie(hi, lo) < std::tie(a.hi, a.lo); }

        constexpr ipv6 to_base(uint8_t mask) const
        {
            ipv6 b;
            if (mask > 64)
            {
                b.hi = hi;
                b.lo = mask < 128 ? (lo >> (128 - mask)) << (128 - mask) : lo;
            }
            else
            {
                b.hi = (hi >> (64 - mask)) << (64 - mask);
                b.lo = 0;
            }
            return b;
        }
    };

    struct ipv6_net
    {
        ipv6 base;
        uint8_t mask;

        const std::string to_string() const { return base.to_base(mask).to_string(); }

        constexpr bool operator==(const ipv6_net& a) { return base == a.base && mask == a.mask; }

        constexpr bool operator!=(const ipv6_net& a) { return not(*this == a); }

        constexpr bool operator<(const ipv6_net& a) { return base.to_base(mask) < a.base.to_base(a.mask); }

        constexpr bool contains(const ipv6& addr) const { return addr.to_base(mask) == base; }
    };

    inline constexpr ipv6_net operator/(const ipv6 a, uint8_t mask)
    {
        return {a.to_base(mask), mask};
    }

    inline constexpr ipv4_net ipv4_loopback = ipv4(127, 0, 0, 1) / 8;
    inline constexpr ipv6 ipv6_loopback(0, 0, 0, 0, 0, 0, 0, 1);

    inline constexpr std::array ipv4_nonpublic = {
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

    inline constexpr std::array ipv6_nonpublic = {
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

    template <>
    inline constexpr bool IsToStringFormattable<ipv4> = true;
    template <>
    inline constexpr bool IsToStringFormattable<ipv6> = true;
    template <>
    inline constexpr bool IsToStringFormattable<ipv4_net> = true;
    template <>
    inline constexpr bool IsToStringFormattable<ipv6_net> = true;
}  //  namespace oxen::quic
