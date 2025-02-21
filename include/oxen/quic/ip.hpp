#pragma once

#include "formattable.hpp"
#include "utils.hpp"

#include <array>

/** IP Addressing Types:
    - ipv{4,6} : These types represent raw ipv4/ipv6 addresses. Both hold their respective addresses in host order
        internally, converting to network order when needed.
    - ipv{4,6}_net : These types hold an extra uint8_t netmask, such that they can represent IP addresses with a netmask,
        such as 1.2.3.4/16, 5.6.7.8/8, and so on. The underlying ipv{4,6} address is stored unmasked as a "networked IP
        address", rather than an "IP network"
    - ipv{4,6}_range : These types represent the above mentioned "IP network" (and the entire range of IP addresses within)
        by storing the masked underlying ipv{4,6} address.

    Example:
        ipv4 v4{"127.8.69.42"};
        v4.to_string();             ->      "127.8.69.42"

        ipv4_net v4_net{ipv4, 16};
        v4_net.to_string();       ->      "127.8.69.42/16"
        v4_net.ip.to_string();    ->      "127.8.69.42"

        ipv4_range v4_range{ipv4, 16};
        v4_range.to_string();       ->      "127.8.0.0/16"
        v4_range.base.to_string();  ->      "127.8.0.0"
*/

namespace oxen::quic
{
    struct ipv4
    {
        // host order
        uint32_t addr;

        constexpr ipv4() = default;

        explicit ipv4(const std::string& str);

        constexpr ipv4(uint32_t a) : addr{a} {}
        constexpr ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) :
                ipv4{uint32_t{a} << 24 | uint32_t{b} << 16 | uint32_t{c} << 8 | uint32_t{d}}
        {}

        constexpr std::optional<ipv4> next_ip() const
        {
            if (not increment_will_overflow(addr))
                return ipv4{addr + 1};

            return std::nullopt;
        }

        explicit operator in_addr() const
        {
            in_addr a;
            a.s_addr = oxenc::host_to_big(addr);
            return a;
        }

        constexpr auto operator<=>(const ipv4& a) const { return addr <=> a.addr; }

        constexpr bool operator==(const ipv4& a) const { return (addr <=> a.addr) == 0; }

        constexpr bool operator==(const in_addr& a) const { return (addr <=> a.s_addr) == 0; }

        constexpr ipv4 to_base(uint8_t mask) const { return mask < 32 ? ipv4{(addr >> (32 - mask)) << (32 - mask)} : *this; }

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };

    struct ipv6
    {
      private:
        // Network order constructor using no length checking of any kind; as a result, it is a foot shotgun,
        // but a useful one for internal usage
        ipv6(const uint8_t* addr) :
                hi{oxenc::load_big_to_host<uint64_t>(addr)}, lo{oxenc::load_big_to_host<uint64_t>(addr + 8)}
        {}

      public:
        // Host order
        uint64_t hi, lo;

        constexpr ipv6() = default;

        explicit ipv6(const std::string& str);

        constexpr std::optional<ipv6> next_ip() const
        {
            // If lo will not overflow, increment and return
            if (not increment_will_overflow(lo))
            {
                ipv6 next{*this};  //  hi is unchanged
                next.lo = lo + 1;
                return next;
            }

            // If lo is INT_MAX, then:
            //  - if hi can be incremented, ++hi and set lo to all 0's
            //  - else, return nullopt
            if (not increment_will_overflow(hi))
            {
                ipv6 next{};  //  lo default set to 0
                next.hi = hi + 1;
                return next;
            }

            return std::nullopt;
        }

        // Network order in6_addr constructor (calls private constructor)
        ipv6(const struct in6_addr* addr) : ipv6{addr->s6_addr} {}

        explicit constexpr ipv6(
                uint16_t a,
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

        in6_addr to_in6() const;

        constexpr auto operator<=>(const ipv6& a) const { return std::tie(hi, lo) <=> std::tie(a.hi, a.lo); }

        constexpr bool operator==(const ipv6& a) const { return (*this <=> a) == 0; }

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
                b.lo = uint64_t{0};
            }
            return b;
        }

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };

    namespace detail
    {
        struct masked_ipv4
        {
            ipv4 ip;
            uint8_t mask;

          protected:
            constexpr masked_ipv4() = default;
            constexpr masked_ipv4(ipv4 b, uint8_t m) : ip{b}, mask{m} {}

          public:
            constexpr ipv4 max_ip() const
            {
                auto b = ip.to_base(mask);

                if (mask < 32)
                    b.addr |= (uint32_t{1} << (32 - mask)) - 2;

                return b;
            }

            constexpr ipv4 broadcast() const
            {
                auto b = ip.to_base(mask);

                if (mask < 32)
                    b.addr |= (uint32_t{1} << (32 - mask)) - 1;

                return b;
            }

            constexpr bool contains(const ipv4& other) const { return other.to_base(mask) == ip; }

            std::string to_string() const;
            constexpr static bool to_string_formattable = true;
        };

        struct masked_ipv6
        {
            ipv6 ip;
            uint8_t mask;

          protected:
            constexpr masked_ipv6() = default;
            constexpr masked_ipv6(ipv6 b, uint8_t m) : ip{b}, mask{m} {}

          public:
            constexpr ipv6 max_ip() const
            {
                auto b = ip.to_base(mask);

                if (mask > 64)
                {
                    b.hi = ip.hi;
                    b.lo |= (uint64_t{1} << (128 - mask)) - 1;
                }
                else
                {
                    b.hi |= (uint64_t{1} << (64 - mask)) - 1;
                    b.lo = ~uint64_t{0};
                }

                return b;
            }

            constexpr bool contains(const ipv6& other) const { return other.to_base(mask) == ip; }

            std::string to_string() const;
            constexpr static bool to_string_formattable = true;
        };
    }  //  namespace detail

    struct ipv4_range : public detail::masked_ipv4
    {
        constexpr ipv4_range() = default;
        constexpr ipv4_range(ipv4 b, uint8_t m) : detail::masked_ipv4{b.to_base(m), m} {}

        constexpr auto operator<=>(const ipv4_range& other) const
        {
            return std::tie(ip, mask) <=> std::tie(other.ip, other.mask);
        }
        constexpr bool operator==(const ipv4_range& other) const { return (*this <=> other) == 0; }
    };

    inline constexpr ipv4_range operator/(const ipv4& a, uint8_t m)
    {
        return {a, m};  // ::to_base() invoked by ctor
    }

    struct ipv4_net : public detail::masked_ipv4
    {
        constexpr ipv4_net() = default;
        constexpr ipv4_net(ipv4 b, uint8_t m) : detail::masked_ipv4{b, m} {}

        constexpr auto operator<=>(const ipv4_net& other) const
        {
            return std::tie(ip, mask) <=> std::tie(other.ip, other.mask);
        }
        constexpr bool operator==(const ipv4_net& other) const { return (*this <=> other) == 0; }

        ipv4_range to_range() const { return ip / mask; }
    };

    inline constexpr ipv4_net operator%(const ipv4& a, uint8_t m)
    {
        return {a, m};
    }

    struct ipv6_range : public detail::masked_ipv6
    {
        constexpr ipv6_range() = default;
        constexpr ipv6_range(ipv6 b, uint8_t m) : detail::masked_ipv6{b.to_base(m), m} {}

        constexpr auto operator<=>(const ipv6_range& other) const
        {
            return std::tie(ip, mask) <=> std::tie(other.ip, other.mask);
        }
        constexpr bool operator==(const ipv6_range& other) const { return (*this <=> other) == 0; }
    };

    inline constexpr ipv6_range operator/(const ipv6& a, uint8_t m)
    {
        return {a, m};  // ::to_base() invoked by ctor
    }

    struct ipv6_net : public detail::masked_ipv6
    {
        constexpr ipv6_net() = default;
        constexpr ipv6_net(ipv6 b, uint8_t m) : detail::masked_ipv6{b, m} {}

        constexpr auto operator<=>(const ipv6_net& other) const
        {
            return std::tie(ip, mask) <=> std::tie(other.ip, other.mask);
        }
        constexpr bool operator==(const ipv6_net& other) const { return (*this <=> other) == 0; }

        ipv6_range to_range() const { return ip / mask; }
    };

    inline constexpr ipv6_net operator%(const ipv6& a, uint8_t m)
    {
        return {a, m};
    }

    inline constexpr ipv4_range ipv4_loopback = ipv4(127, 0, 0, 1) / 8;
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
}  //  namespace oxen::quic
