#pragma once

#include "formattable.hpp"
#include "ip.hpp"
#include "types.hpp"

#include <oxenc/endian.h>

#include <compare>

#if defined(__OpenBSD__) || defined(__DragonFly__)
// These systems are known to disallow dual stack binding, and so on such systems when
// invoked with an empty address we default to the IPv4 any address rather than the IPv6 any
// address as the IPv4 is very likely to be more usable.
//
// A libquic-using application that wants to support full dual stack on these OSes as well
// will need to modify how they use QUIC to maintain *two* endpoints: one bound to `[::]`
// and one bound to `0.0.0.0`.  (Using such an explicit address instead of a
// default-constructed or empty IP address will not be dual stack anywhere).  Alternatively an
// application can use this OXEN_LIBQUIC_ADDRESS_NO_DUAL_STACK definition to figure something out.
#define OXEN_LIBQUIC_ADDRESS_NO_DUAL_STACK
#endif

namespace oxen::quic
{
    inline constexpr std::array<uint8_t, 16> _ipv6_any_addr = {0};

    struct Address;

    inline namespace concepts
    {
        template <typename T>
        concept raw_sockaddr_type =
                std::same_as<T, sockaddr> || std::same_as<T, sockaddr_in> || std::same_as<T, sockaddr_in6>;

        template <typename T>
        concept quic_address_type = std::derived_from<T, Address>;
    }  // namespace concepts

    // Holds an address, with a ngtcp2_addr held for easier passing into ngtcp2 functions
    struct Address
    {
        friend class TestHelper;

      private:
        sockaddr_storage _sock_addr{};
        ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), 0};

      protected:
        void _copy_internals(const Address& obj)
        {
            std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
            _addr.addrlen = obj._addr.addrlen;
            dual_stack = obj.dual_stack;
        }

      public:
        /// Default constructor or single-port constructor yields [::]:port (or [::]:0 if port
        /// omitted) on most platforms where dual-stack IPv6/IPv4 sockets are supported.  On OSes
        /// that do not allow dual-stack sockets (OpenBSD, DragonFlyBSD) the default for an empty IP
        /// address is instead the IPv4 any address (0.0.0.0).
        explicit Address(uint16_t port = 0) : Address{"", port} {}

        Address(const sockaddr* s, socklen_t n)
        {
            std::memmove(&_sock_addr, s, n);
            _addr.addrlen = n;
        }
        explicit Address(const sockaddr* s) :
                Address{s, static_cast<socklen_t>(s->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6))}
        {}
        explicit Address(const sockaddr_in* s) : Address{reinterpret_cast<const sockaddr*>(s), sizeof(sockaddr_in)} {}
        explicit Address(const sockaddr_in6* s) : Address{reinterpret_cast<const sockaddr*>(s), sizeof(sockaddr_in6)} {}
        Address(const std::string& addr, uint16_t port);

        explicit Address(const ngtcp2_addr& addr);

        explicit Address(const ipv4& v4, uint16_t port = 0);

        explicit Address(const ipv6& v6, uint16_t port = 0);

        // Assignment from a sockaddr pointer; we copy the sockaddr's contents
        template <concepts::raw_sockaddr_type T>
        Address& operator=(const T* s)
        {
            _addr.addrlen = std::is_same_v<T, sockaddr>
                                  ? s->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)
                                  : sizeof(T);
            std::memmove(&_sock_addr, s, _addr.addrlen);
            return *this;
        }

        Address(const Address& obj) { _copy_internals(obj); }
        Address& operator=(const Address& obj)
        {
            _copy_internals(obj);
            return *this;
        }

        // If true and this Address is IPv6 then QUIC will set the IPV6_V6ONLY socket option when
        // binding the socket.  This will default to true *only* for default-constructed any
        // addresses; if an explicit address is given (including the `[::]` IPv6 any-address) then
        // this will remain false, and the socket will not be dual-stack unless this is manually
        // set to true before binding.  (Note that manually setting it to true on systems where the
        // socket option cannot be set will cause a failure during endpoint binding).
        bool dual_stack = false;

        void set_port(uint16_t port)
        {
            if (_sock_addr.ss_family == AF_INET6)
            {
                auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
                sin6.sin6_port = oxenc::host_to_big(port);
            }
            else if (_sock_addr.ss_family == AF_INET)
            {
                auto& sin4 = reinterpret_cast<sockaddr_in&>(_sock_addr);
                sin4.sin_port = oxenc::host_to_big(port);
            }
            else
                throw std::invalid_argument{"Error: could not set port in unknown sock_addr"};
        }

        // Helpers for setting the IP (only, not the port!) from C networking code
        void set_addr(const struct in_addr* addr);
        void set_addr(const struct in6_addr* addr);

        // Converts an IPv4 address into an IPv4-mapped IPv6 address.  The address must already be
        // an IPv4 address (throws if not).
        void map_ipv4_as_ipv6();

        // Returns true if this address is an IPv4-mapped IPv6 address.
        bool is_ipv4_mapped_ipv6() const;

        // Undoes `map_ipv4_as_ipv6`, converting the address to an IPv4 address; the address must be
        // a IPv4-mapped IPv6 address (throws if not).
        void unmap_ipv4_from_ipv6();

        // Wrappers around map_.../unmap_... that return a mapped/unmapped copy.
        Address mapped_ipv4_as_ipv6() const
        {
            Address tmp{*this};
            tmp.map_ipv4_as_ipv6();
            return tmp;
        }
        Address unmapped_ipv4_from_ipv6() const
        {
            Address tmp{*this};
            tmp.unmap_ipv4_from_ipv6();
            return tmp;
        }

        bool is_set() const { return is_ipv4() || is_ipv6(); }

        /// Returns true if this is the "any" address ("::" for ipv6, "0.0.0.0" for IPv4)
        bool is_any_addr() const
        {
            return is_ipv4()
                         ? in4().sin_addr.s_addr == 0
                         : std::memcmp(in6().sin6_addr.s6_addr, _ipv6_any_addr.data(), sizeof(in6().sin6_addr.s6_addr)) == 0;
        }

        /// Returns true if this is the "any" port (port 0)
        bool is_any_port() const { return (is_ipv4() ? in4().sin_port : in6().sin6_port) == 0; }

        /// Returns true if this is an addressable address, i.e. not the "any" address or port
        bool is_addressable() const { return !is_any_addr() && !is_any_port(); }

        /// Returns true if this is an addressable, public IP and port (i.e. addressable and not in
        /// a private range).
        bool is_public() const;

        /// Returns true if this has an addressable public IP (but unlike `is_public()` this allows
        /// port to be set to the 0 "any port").
        bool is_public_ip() const;

        /// Returns true if this address is a loopback address (IPv4 127.0.0.0/8 or IPv6 ::1)
        bool is_loopback() const;

        inline bool is_ipv4() const
        {
            return _addr.addrlen == sizeof(sockaddr_in) &&
                   reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_family == AF_INET;
        }

        inline bool is_ipv6() const
        {
            return _addr.addrlen == sizeof(sockaddr_in6) &&
                   reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_family == AF_INET6;
        }

        ipv4 to_ipv4() const;

        ipv6 to_ipv6() const;

        // Accesses the sockaddr_in for this address.  Precondition: `is_ipv4()`
        inline const sockaddr_in& in4() const
        {
            assert(is_ipv4());
            return reinterpret_cast<const sockaddr_in&>(_sock_addr);
        }

        // Accesses the sockaddr_in6 for this address.  Precondition: `is_ipv6()`
        inline const sockaddr_in6& in6() const
        {
            assert(is_ipv6());
            return reinterpret_cast<const sockaddr_in6&>(_sock_addr);
        }

        inline uint16_t port() const
        {
            assert(is_ipv4() || is_ipv6());

            return oxenc::big_to_host(
                    is_ipv4() ? reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_port
                              : reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_port);
        }

        // template code to implicitly convert to sockaddr*, sockaddr_in*, sockaddr_in6* so that
        // this can be passed into C functions taking such a pointer (for the first you also want
        // `socklen()`).
        //
        // Because this is a deducated templated type, dangerous implicit conversions from the
        // pointer to other things (like bool) won't occur.
        //
        // If the given pointer is mutated you *must* call update_socklen() afterwards.
        template <concepts::raw_sockaddr_type T>
        operator T*()
        {
            return reinterpret_cast<T*>(&_sock_addr);
        }
        template <concepts::raw_sockaddr_type T>
        operator const T*() const
        {
            return reinterpret_cast<const T*>(&_sock_addr);
        }

        // Conversion to a const ngtcp2_addr reference and pointer.  We don't provide non-const
        // access because this points at our internal data.
        operator const ngtcp2_addr&() const { return _addr; }
        template <typename T>
            requires std::same_as<T, ngtcp2_addr>
        operator const T*() const
        {
            return &_addr;
        }

        auto operator<=>(const Address& other) const
        {
            if (is_ipv4() && other.is_ipv4())
            {
                auto& a = in4();
                auto& b = other.in4();
                if (auto r = memcmp(&a.sin_addr.s_addr, &b.sin_addr.s_addr, sizeof(a.sin_addr.s_addr)); r != 0)
                    return r <=> 0;
                return oxenc::big_to_host(a.sin_port) <=> oxenc::big_to_host(b.sin_port);
            }

            if (is_ipv6() && other.is_ipv6())
            {
                auto& a = in6();
                auto& b = other.in6();
                if (auto r = memcmp(a.sin6_addr.s6_addr, b.sin6_addr.s6_addr, sizeof(a.sin6_addr.s6_addr)); r != 0)
                    return r <=> 0;
                return oxenc::big_to_host(a.sin6_port) <=> oxenc::big_to_host(b.sin6_port);
            }
            return is_ipv6() <=> other.is_ipv6();
        }

        bool operator==(const Address& other) const { return (*this <=> other) == 0; }

        // Returns the size of the sockaddr
        socklen_t socklen() const { return _addr.addrlen; }

        // Returns a pointer to the sockaddr size; typically you want this when updating the address
        // via a function like `getsockname`.
        socklen_t* socklen_ptr() { return &_addr.addrlen; }

        // Updates the socklen of the sockaddr; this must be called if directly modifying the
        // address via one of the sockaddr* pointer operators.  (It is not needed when assigning a
        // sockaddr pointer).
        void update_socklen(socklen_t len) { _addr.addrlen = len; }

        std::string host() const;

        // Convenience method for debugging, etc.  This is usually called implicitly by passing the
        // Address to fmt to format it.
        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };

    struct RemoteAddress : public Address
    {
      private:
        std::vector<unsigned char> _remote_pubkey;

      public:
        RemoteAddress() = delete;

        template <typename... Opt>
        RemoteAddress(std::string_view remote_pk, Opt&&... opts) :
                Address{std::forward<Opt>(opts)...}, _remote_pubkey(remote_pk.size())
        {
            std::memcpy(_remote_pubkey.data(), remote_pk.data(), remote_pk.size());
        }

        template <typename... Opt>
        RemoteAddress(uspan remote_pk, Opt&&... opts) : Address{std::forward<Opt>(opts)...}
        {
            _remote_pubkey.assign(remote_pk.data(), remote_pk.data() + remote_pk.size());
        }

        uspan view_remote_key() const { return _remote_pubkey; }
        const std::vector<unsigned char>& get_remote_key() const& { return _remote_pubkey; }
        std::vector<unsigned char>&& get_remote_key() && { return std::move(_remote_pubkey); }

        RemoteAddress(const RemoteAddress& obj) = default;
        RemoteAddress& operator=(const RemoteAddress& obj) = default;
        RemoteAddress(RemoteAddress&& other) = default;
        RemoteAddress& operator=(RemoteAddress&& other) = default;

        auto operator<=>(const RemoteAddress& other) const
        {
            auto ret = _remote_pubkey <=> other._remote_pubkey;
            if (ret == 0)
                ret = Address::operator<=>(other);
            return ret;
        }
        auto operator==(const RemoteAddress& other) const { return (*this <=> other) == 0; }
    };

    // Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    // to ngtcp2_path*
    struct Path
    {
        friend class TestHelper;
        friend class Connection;

      public:
        Address local;
        Address remote;

      private:
        ngtcp2_path _path{local, remote, nullptr};

        void set_new_remote(const ngtcp2_addr& new_remote);

      public:
        Path() = default;
        Path(const Address& l, const Address& r) : local{l}, remote{r} {}
        Path(const Path& p) : Path{p.local, p.remote} {}

        Path& operator=(const Path& p)
        {
            local = p.local;
            remote = p.remote;
            _path.local = local;
            _path.remote = remote;
            return *this;
        }

        bool operator==(const Path& other) const { return std::tie(local, remote) == std::tie(other.local, other.remote); }

        // template code to pass Path as ngtcp2_path into ngtcp2 functions
        template <typename T>
            requires std::same_as<T, ngtcp2_path>
        operator T*()
        {
            return &_path;
        }
        template <typename T>
            requires std::same_as<T, ngtcp2_path>
        operator const T*() const
        {
            return &_path;
        }

        Path invert() const { return {remote, local}; }

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };
}  // namespace oxen::quic

namespace std
{
    template <>
    struct hash<oxen::quic::Address>
    {
        size_t operator()(const oxen::quic::Address& addr) const noexcept
        {
            std::string_view addr_data;
            uint16_t port;
            if (addr.is_ipv4())
            {
                auto& ip4 = addr.in4();
                addr_data = {reinterpret_cast<const char*>(&ip4.sin_addr.s_addr), sizeof(ip4.sin_addr.s_addr)};
                port = ip4.sin_port;
            }
            else
            {
                assert(addr.is_ipv6());
                auto& ip6 = addr.in6();
                addr_data = {reinterpret_cast<const char*>(ip6.sin6_addr.s6_addr), sizeof(ip6.sin6_addr.s6_addr)};
                port = ip6.sin6_port;
            }

            auto h = hash<string_view>{}(addr_data);
            h ^= hash<decltype(port)>{}(port) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };

    template <>
    struct hash<oxen::quic::RemoteAddress>
    {
        size_t operator()(const oxen::quic::RemoteAddress& addr) const noexcept
        {
            auto vrk = addr.view_remote_key();
            size_t h = hash<std::string_view>{}(std::string_view{reinterpret_cast<const char*>(vrk.data()), vrk.size()});
            h ^= hash<oxen::quic::Address>{}(addr) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };

    template <>
    struct hash<oxen::quic::Path>
    {
        size_t operator()(const oxen::quic::Path& addr) const noexcept
        {
            auto h = hash<oxen::quic::Address>{}(addr.local);
            h ^= hash<oxen::quic::Address>{}(addr.remote) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };
}  // namespace std
