#pragma once

extern "C"
{
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <sys/socket.h>
}

#include <fmt/core.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <uvw.hpp>

/*
 * Example 1: Handshake with www.google.com
 *
 * #define REMOTE_HOST "www.google.com"
 * #define REMOTE_PORT "443"
 * #define ALPN "\x2h3"
 *
 * and undefine MESSAGE macro.
 */

#define MESSAGE "GET /\r\n"

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    class Stream;

    using namespace std::literals;
    using namespace oxen::log::literals;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;
    namespace log = oxen::log;

    // SI (1000) and non-SI (1024-based) modifier prefix operators.  E.g.
    // 50_M is 50'000'000 and 50_Mi is 52'428'800.
    constexpr unsigned long long operator""_k(unsigned long long int x)
    {
        return x * 1000;
    }
    constexpr unsigned long long operator""_M(unsigned long long int x)
    {
        return x * 1000 * 1_k;
    }
    constexpr unsigned long long operator""_G(unsigned long long int x)
    {
        return x * 1000 * 1_M;
    }
    constexpr unsigned long long operator""_T(unsigned long long int x)
    {
        return x * 1000 * 1_G;
    }

    constexpr unsigned long long operator""_ki(unsigned long long int x)
    {
        return x * 1024;
    }
    constexpr unsigned long long operator""_Mi(unsigned long long int x)
    {
        return x * 1024 * 1_ki;
    }
    constexpr unsigned long long operator""_Gi(unsigned long long int x)
    {
        return x * 1024 * 1_Mi;
    }
    constexpr unsigned long long operator""_Ti(unsigned long long int x)
    {
        return x * 1024 * 1_Gi;
    }

    // Callbacks for async calls
    using async_callback_t = std::function<void(const uvw::async_event& event, uvw::async_handle& udp)>;
    // Callbacks for opening quic connections and closing tunnels
    using open_callback = std::function<void(bool success, void* user_data)>;
    using close_callback = std::function<void(int rv, void* user_data)>;
    // Callbacks for ev timer functionality
    using read_callback = std::function<void(uvw::loop* loop, uvw::timer_event* ev, int revents)>;
    using timer_callback = std::function<void(int nwrite, void* user_data)>;

    // Stream callbacks
    using stream_data_callback_t = std::function<void(Stream&, bstring_view)>;
    using stream_close_callback_t = std::function<void(Stream&, uint64_t error_code)>;
    // returns 0 on success
    using stream_open_callback_t = std::function<uint64_t(Stream&)>;
    using unblocked_callback_t = std::function<bool(Stream&)>;

    inline constexpr uint64_t DEFAULT_MAX_BIDI_STREAMS = 32;

    // Maximum number of packets we can send in one batch when using sendmmsg/GSO
    inline constexpr size_t DATAGRAM_BATCH_SIZE = 24;

    inline constexpr std::byte CLIENT_TO_SERVER{1};
    inline constexpr std::byte SERVER_TO_CLIENT{2};
    inline constexpr size_t dgram_size = 1200;
    inline constexpr size_t ev_loop_queue_size = 1024;

    // Check if T is an instantiation of templated class `Class`; for example,
    // `is_instantiation<std::basic_string, std::string>` is true.
    template <template <typename...> class Class, typename T>
    inline constexpr bool is_instantiation = false;
    template <template <typename...> class Class, typename... Us>
    inline constexpr bool is_instantiation<Class, Class<Us...>> = true;

    // Max theoretical size of a UDP packet is 2^16-1 minus IP/UDP header overhead
    inline constexpr size_t max_bufsize = 64_ki;
    // Max size of a UDP packet that we'll send
    inline constexpr size_t max_pkt_size = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;

    // Remote TCP connection was established and is now accepting stream data; the client is not
    // allowed to send any other data down the stream until this comes back (any data sent down the
    // stream before then is discarded)
    inline constexpr std::byte CONNECT_INIT{0x00};
    // Failure to establish an initial connection:
    inline constexpr uint64_t ERROR_CONNECT{0x5471907};
    // Error for something other than CONNECT_INIT as the initial stream data from the server
    inline constexpr uint64_t ERROR_BAD_INIT{0x5471908};
    // Close error code sent if we get an error on the TCP socket (other than an initial connect
    // failure)
    inline constexpr uint64_t ERROR_TCP{0x5471909};
    // Application error code we close with if the data handle throws
    inline constexpr uint64_t STREAM_ERROR_EXCEPTION = (1ULL << 62) - 2;
    // Error code we send to a stream close callback if the stream's connection expires
    inline constexpr uint64_t STREAM_ERROR_CONNECTION_EXPIRED = (1ULL << 62) + 1;

    // bstring_view literals baby
    inline std::basic_string_view<std::byte> operator""_bsv(const char* __str, size_t __len) noexcept
    {
        return std::basic_string_view<std::byte>(reinterpret_cast<const std::byte*>(__str), __len);
    }

    // We pause reading from the local TCP socket if we have more than this amount of outstanding
    // unacked data in the quic tunnel, then resume once it drops below this.
    inline constexpr size_t PAUSE_SIZE = 64_ki;

    // For templated parameter strict type checking
    template <typename Base, typename T>
    constexpr bool is_strict_base_of_v = std::is_base_of_v<Base, T> && !std::is_same_v<Base, T>;

    // Types can opt-in to being formatting via .to_string() by specializing this to true
    template <typename T>
    constexpr bool IsToStringFormattable = false;

    // We send and verify this in the initial connection and handshake; this is designed to allow
    // future changes (by either breaking or handling backwards compat).
    constexpr const std::array<uint8_t, 8> handshake_magic_bytes{'l', 'o', 'k', 'i', 'n', 'e', 't', 0x01};
    constexpr std::basic_string_view<uint8_t> handshake_magic{handshake_magic_bytes.data(), handshake_magic_bytes.size()};

    const char test_priority[] =
            "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
            "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
            "+GROUP-SECP384R1:"
            "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

    void logger_config(std::string out = "stderr", log::Type type = log::Type::Print, log::Level reset = log::Level::trace);

    std::chrono::steady_clock::time_point get_time();
    uint64_t get_timestamp();

    std::string str_tolower(std::string s);

    std::mt19937 make_mt19937();

    inline int numeric_host_family(const char* hostname, int family)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint8_t dst[sizeof(struct in6_addr)];
        return inet_pton(family, hostname, dst) == 1;
    }

    inline int numeric_host(const char* hostname)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return numeric_host_family(hostname, AF_INET) || numeric_host_family(hostname, AF_INET6);
    }

    // Wrapper for ngtcp2_cid with helper functionalities to make it passable
    struct alignas(size_t) ConnectionID : ngtcp2_cid
    {
        ConnectionID() = default;
        ConnectionID(const ConnectionID& c) = default;
        ConnectionID(const uint8_t* cid, size_t length);
        ConnectionID(ngtcp2_cid c) : ConnectionID(c.data, c.datalen) {}

        ConnectionID& operator=(const ConnectionID& c) = default;

        inline bool operator==(const ConnectionID& other) const
        {
            return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
        }
        inline bool operator!=(const ConnectionID& other) const { return !(*this == other); }
        static ConnectionID random();

        std::string to_string() const;
    };
    template <>
    constexpr inline bool IsToStringFormattable<ConnectionID> = true;

    // Wrapper for address types with helper functionalities, operators, etc. By inheriting from
    // uvw::Addr, we are able to use string/uint16_t representations of host/port through the API
    // interface and in the constructors. The string/uint16_t representation is stored in a two
    // other formats for ease of use with ngtcp2: sockaddr_in and ngtcp2_addr. ngtcp2_addr store
    // a member of type ngtcp2_sockaddr, which is itself a typedef of sockaddr
    struct Address
    {
      private:
        sockaddr_storage _sock_addr{};
        ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), 0};

        void _copy_internals(const Address& obj)
        {
            std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
            _addr.addrlen = obj._addr.addrlen;
        }

      public:
        // Default constructor yields [::]:0
        Address() { _addr.addrlen = sizeof(sockaddr_in6); }

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

        bool is_ipv4() const
        {
            return _addr.addrlen == sizeof(sockaddr_in) &&
                   reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_family == AF_INET;
        }
        bool is_ipv6() const
        {
            return _addr.addrlen == sizeof(sockaddr_in6) &&
                   reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_family == AF_INET6;
        }

        // Accesses the sockaddr_in for this address.  Precondition: `is_ipv4()`
        const sockaddr_in& in4() const
        {
            assert(is_ipv4());
            return reinterpret_cast<const sockaddr_in&>(_sock_addr);
        }

        // Accesses the sockaddr_in6 for this address.  Precondition: `is_ipv6()`
        const sockaddr_in6& in6() const
        {
            assert(is_ipv6());
            return reinterpret_cast<const sockaddr_in6&>(_sock_addr);
        }

        uint16_t port() const
        {
            assert(is_ipv4() || is_ipv6());
            return is_ipv4() ? reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_port
                             : reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_port;
        }

        // template code to implicitly convert to sockaddr*, sockaddr_in*, sockaddr_in6* so that
        // this can be passed into C functions taking such a pointer (for the first you also want
        // `socklen()`).
        //
        // Because this is a deducated templated type, dangerous implicit conversions from the
        // pointer to other things (like bool) won't occur.
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
                return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
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

        // Returns the size of the sockaddr
        socklen_t socklen() const { return _addr.addrlen; }

        // Convenience method for debugging, etc.  This is usually called implicitly by passing the
        // Address to fmt to format it.
        std::string to_string() const;
    };
    template <>
    inline constexpr bool IsToStringFormattable<Address> = true;

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

    // Simple struct wrapping a packet and its corresponding information
    struct Packet
    {
        Path path;
        bstring_view data;
        ngtcp2_pkt_info pkt_info;
    };

    struct libuv_error_code_t final
    {};
    struct ngtcp2_error_code_t final
    {};

    // Tag values to pass into the constructor to indicate a libuv or ngtcp2 error code.
    //
    // (On unixy systems, libuv error codes are the negatives of errno codes, but on Windows they
    // are arbitrary values, so they have to be handled differently).
    //
    // (For ngtcp2, error codes are arbitrary negative values without any connection to errno).
    static inline constexpr libuv_error_code_t libuv_error_code{};
    static inline constexpr ngtcp2_error_code_t ngtcp2_error_code{};

    // Struct returned as a result of send_packet that either is implicitly
    // convertible to bool, but also is able to carry an error code
    struct io_result
    {

        // Default construction makes a "good" io_result, i.e. with error code 0
        io_result() : io_result{0} {}

        // Constructs an io_result with an `errno` value.
        explicit io_result(int errno_val) : error_code{errno_val} {}

        // Constructs an io_result with a libuv error value.
        io_result(int err, libuv_error_code_t) : error_code{err}, is_libuv{true} {}

        // Constructs an io_result with an ngtcp2 error value.
        io_result(int err, ngtcp2_error_code_t) : error_code{err}, is_libuv{true} {}

        // Same as the libuv error code constructor
        static io_result libuv(int err) { return io_result{err, libuv_error_code}; }

        // Same as the ngtcp2 error code constructor
        static io_result ngtcp2(int err) { return io_result{err, ngtcp2_error_code}; }

        // The numeric error code
        int error_code{0};
        // If true then `error_code` is a libuv/ngtcp2 error code, rather than an errno value.
        bool is_libuv = false, is_ngtcp2 = false;
        // Returns true if this indicates success, i.e. error code of 0
        bool success() const { return error_code == 0; }
        // Returns true if this indicates failure, i.e. error code not 0
        bool failure() const { return !success(); }
        // returns true if error value indicates a failure to write without blocking
        bool blocked() const
        {
            return is_libuv  ? error_code == UV_EAGAIN
                 : is_ngtcp2 ? error_code == NGTCP2_ERR_STREAM_DATA_BLOCKED
                             : (error_code == EAGAIN || error_code == EWOULDBLOCK);
        }
        // returns the error message string describing error_code
        std::string_view str() const;
    };

    // Shortcut for a const-preserving `reinterpret_cast`ing c.data() from a std::byte to a uint8_t
    // pointer, because we need it all over the place in the ngtcp2 API
    template <
            typename Container,
            typename = std::enable_if_t<sizeof(typename std::remove_reference_t<Container>::value_type) == sizeof(uint8_t)>>
    auto* u8data(Container&& c)
    {
        using u8_sameconst_t =
                std::conditional_t<std::is_const_v<std::remove_pointer_t<decltype(c.data())>>, const uint8_t, uint8_t>;
        return reinterpret_cast<u8_sameconst_t*>(c.data());
    }

    // Stringview conversion function to interoperate between bstring_views and any other potential
    // user supplied type
    template <typename CharOut, typename CharIn, typename = std::enable_if_t<sizeof(CharOut) == 1 && sizeof(CharIn) == 1>>
    std::basic_string_view<CharOut> convert_sv(std::basic_string_view<CharIn> in)
    {
        return {reinterpret_cast<const CharOut*>(in.data()), in.size()};
    }

    // Namespacing for named address arguments in API calls
    namespace opt
    {}  // namespace opt

    struct buffer_printer
    {
        std::basic_string_view<std::byte> buf;

        // Constructed from any type of string_view<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string_view<T> buf) :
                buf{reinterpret_cast<const std::byte*>(buf.data()), buf.size()}
        {}

        // Constructed from any type of lvalue string<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const std::basic_string<T>& buf) : buffer_printer(std::basic_string_view<T>{buf})
        {}

        // *Not* constructable from a string<T> rvalue (because we only hold a view and do not take
        // ownership).
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string<T>&& buf) = delete;

        // Constructable from a (T*, size) argument pair, for byte-sized T's.
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const T* data, size_t size) : buffer_printer(std::basic_string_view<T>{data, size})
        {}

        std::string to_string() const;
    };

    template <>
    inline constexpr bool IsToStringFormattable<buffer_printer> = true;

}  // namespace oxen::quic

namespace std
{
    // Custom hash is required s.t. unordered_set storing ConnectionID:unique_ptr<Connection>
    // is able to call its implicit constructor
    template <>
    struct hash<oxen::quic::ConnectionID>
    {
        size_t operator()(const oxen::quic::ConnectionID& cid) const
        {
            static_assert(
                    alignof(oxen::quic::ConnectionID) >= alignof(size_t) &&
                    offsetof(oxen::quic::ConnectionID, data) % sizeof(size_t) == 0);
            return *reinterpret_cast<const size_t*>(cid.data);
        }
    };

    inline constexpr size_t inverse_golden_ratio = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

    template <>
    struct hash<oxen::quic::Address>
    {
        size_t operator()(const oxen::quic::Address& addr) const
        {
            std::string_view addr_data;
            in_port_t port;
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
            h ^= hash<in_port_t>{}(port) + inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };
}  // namespace std

namespace fmt
{
    template <typename T>
    struct formatter<T, char, std::enable_if_t<oxen::quic::IsToStringFormattable<T>>> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(val.to_string(), ctx);
        }
    };

}  // namespace fmt
