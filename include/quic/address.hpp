#pragma once

#include "format.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline constexpr std::array<uint8_t, 16> _ipv6_any_addr = {0};

    // Holds an address, with a ngtcp2_addr held for easier passing into ngtcp2 functions
    struct Address
    {
      private:
        sockaddr_storage _sock_addr{};
        ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), 0};

      protected:
        void _copy_internals(const Address& obj)
        {
            std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
            _addr.addrlen = obj._addr.addrlen;
        }

      public:
        // Default constructor or single-port constructor yields [::]:port (or [::]:0 if port omitted)
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

        // Assignment from a sockaddr pointer; we copy the sockaddr's contents
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr>,
                        int> = 0>
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
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr_in6>,
                        int> = 0>
        operator T*()
        {
            return reinterpret_cast<T*>(&_sock_addr);
        }
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr_in6>,
                        int> = 0>
        operator const T*() const
        {
            return reinterpret_cast<const T*>(&_sock_addr);
        }

        // Conversion to a const ngtcp2_addr reference and pointer.  We don't provide non-const
        // access because this points at our internal data.
        operator const ngtcp2_addr&() const { return _addr; }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_addr*>, int> = 0>
        operator const T*() const
        {
            return &_addr;
        }

        bool operator==(const Address& other) const
        {
            if (is_ipv4() && other.is_ipv4())
            {
                auto& a = in4();
                auto& b = other.in4();
                return a.sin_port == b.sin_port &&
                       memcmp(&a.sin_addr.s_addr, &b.sin_addr.s_addr, sizeof(a.sin_addr.s_addr)) == 0;
            }
            if (is_ipv6() && other.is_ipv6())
            {
                auto& a = in6();
                auto& b = other.in6();
                return a.sin6_port == b.sin6_port &&
                       memcmp(a.sin6_addr.s6_addr, b.sin6_addr.s6_addr, sizeof(a.sin6_addr.s6_addr)) == 0;
            }
            return false;
        }

        bool operator<(const Address& other) const
        {
            if (is_ipv4() && other.is_ipv4())
            {
                auto& a = in4();
                auto& b = other.in4();

                if (auto r = memcmp(&a.sin_addr.s_addr, &b.sin_addr.s_addr, sizeof(a.sin_addr.s_addr)); r == 0)
                    return a.sin_port < b.sin_port;
                else
                    return (r < 0);
            }
            if (is_ipv6() && other.is_ipv6())
            {
                auto& a = in6();
                auto& b = other.in6();

                if (auto r = memcmp(a.sin6_addr.s6_addr, b.sin6_addr.s6_addr, sizeof(a.sin6_addr.s6_addr)); r == 0)
                    return a.sin6_port < b.sin6_port;
                else
                    return (r < 0);
            }
            if (is_ipv6() && other.is_ipv4())
                return false;
            return true;
        }

        bool operator!=(const Address& other) const { return !(*this == other); }

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
    };
    template <>
    inline constexpr bool IsToStringFormattable<Address> = true;

    struct RemoteAddress : public Address
    {
      private:
        ustring remote_pubkey;

      public:
        RemoteAddress() = delete;

        template <typename... Opt>
        RemoteAddress(std::string_view remote_pk, Opt&&... opts) :
                Address{std::forward<Opt>(opts)...}, remote_pubkey{to_usv(remote_pk)}
        {}

        template <typename... Opt>
        RemoteAddress(ustring_view remote_pk, Opt&&... opts) : Address{std::forward<Opt>(opts)...}, remote_pubkey{remote_pk}
        {}

        ustring_view view_remote_key() const { return remote_pubkey; }
        const ustring& get_remote_key() const& { return remote_pubkey; }
        ustring&& get_remote_key() && { return std::move(remote_pubkey); }

        RemoteAddress(const RemoteAddress& obj) : Address{obj}, remote_pubkey{obj.remote_pubkey} {}
        RemoteAddress& operator=(const RemoteAddress& obj)
        {
            remote_pubkey = obj.remote_pubkey;
            Address::operator=(obj);
            _copy_internals(obj);
            return *this;
        }
    };
    template <>
    inline constexpr bool IsToStringFormattable<RemoteAddress> = true;

    // Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    // to ngtcp2_path*
    struct Path
    {
      public:
        Address local;
        Address remote;

      private:
        ngtcp2_path _path{local, remote, nullptr};

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

        // template code to pass Path as ngtcp2_path into ngtcp2 functions
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator T*()
        {
            return &_path;
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator const T*() const
        {
            return &_path;
        }

        std::string to_string() const;
    };
    template <>
    inline constexpr bool IsToStringFormattable<Path> = true;

}  // namespace oxen::quic

namespace std
{
    inline constexpr size_t inverse_golden_ratio = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

    template <>
    struct hash<oxen::quic::Address>
    {
        size_t operator()(const oxen::quic::Address& addr) const
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
            h ^= hash<decltype(port)>{}(port) + inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };
}  // namespace std
