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

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <oxen/log.hpp>
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

static auto log_cat = oxen::log::Cat("quic");

namespace oxen::quic
{
    class Stream;

    using namespace std::literals;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;
    namespace log = oxen::log;

    // Callbacks for async calls
    using async_callback_t = std::function<void(const uvw::AsyncEvent& event, uvw::AsyncHandle& udp)>;
    // Callbacks for opening quic connections and closing tunnels
    using open_callback = std::function<void(bool success, void* user_data)>;
    using close_callback = std::function<void(int rv, void* user_data)>;
    // Callbacks for ev timer functionality
    using read_callback = std::function<void(uvw::Loop* loop, uvw::TimerEvent* ev, int revents)>;
    using timer_callback = std::function<void(int nwrite, void* user_data)>;
    // Callbacks for client/server TLS connectivity and authentication
    using server_tls_callback_t = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;
    using client_tls_callback_t = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;
    // Callbacks for embedding in client/server UVW events (ex: listen events, data events, etc)
    using server_data_callback_t = std::function<void(const uvw::UDPDataEvent& event, uvw::UDPHandle& udp)>;
    // Stream callbacks
    using stream_data_callback_t = std::function<void(Stream&, bstring_view)>;
    using stream_close_callback_t = std::function<void(Stream&, uint64_t error_code)>;
    // returns 0 on success
    using stream_open_callback_t = std::function<uint64_t(Stream&)>;
    using unblocked_callback_t = std::function<bool(Stream&)>;
    // send buffer types
    static constexpr size_t batch_size = 8;
    using send_buffer_t = std::array<std::pair<std::array<std::byte, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE>, size_t>, batch_size>;

    static constexpr std::byte CLIENT_TO_SERVER{1};
    static constexpr std::byte SERVER_TO_CLIENT{2};
    static constexpr size_t dgram_size = 1200;
    static constexpr size_t ev_loop_queue_size = 1024;

    // Check if T is an instantiation of templated class `Class`; for example,
    // `is_instantiation<std::basic_string, std::string>` is true.
    template <template <typename...> class Class, typename T>
    inline constexpr bool is_instantiation = false;
    template <template <typename...> class Class, typename... Us>
    inline constexpr bool is_instantiation<Class, Class<Us...>> = true;

    // Max theoretical size of a UDP packet is 2^16-1 minus IP/UDP header overhead
    static constexpr size_t max_bufsize = 64 * 1024;
    // Max size of a UDP packet that we'll send
    static constexpr size_t max_pkt_size_v4 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
    static constexpr size_t max_pkt_size_v6 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

    // Remote TCP connection was established and is now accepting stream data; the client is not
    // allowed to send any other data down the stream until this comes back (any data sent down the
    // stream before then is discarded)
    static constexpr std::byte CONNECT_INIT{0x00};
    // Failure to establish an initial connection:
    static constexpr uint64_t ERROR_CONNECT{0x5471907};
    // Error for something other than CONNECT_INIT as the initial stream data from the server
    static constexpr uint64_t ERROR_BAD_INIT{0x5471908};
    // Close error code sent if we get an error on the TCP socket (other than an initial connect
    // failure)
    static constexpr uint64_t ERROR_TCP{0x5471909};
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
    inline constexpr size_t PAUSE_SIZE = 64 * 1024;

    // For templated parameter strict type checking
    template <typename Base, typename T>
    constexpr bool is_strict_base_of_v = std::is_base_of_v<Base, T> && !std::is_same_v<Base, T>;

    // Types can opt-in to being formatting via .ToString() by specializing this to true
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
    };

    // Wrapper for address types with helper functionalities, operators, etc. By inheriting from
    // uvw::Addr, we are able to use string/uint16_t representations of host/port through the API
    // interface and in the constructors. The string/uint16_t representation is stored in a two
    // other formats for ease of use with ngtcp2: sockaddr_in and ngtcp2_addr. ngtcp2_addr store
    // a member of type ngtcp2_sockaddr, which is itself a typedef of sockaddr
    struct Address : public uvw::Addr
    {
      private:
        sockaddr_in _sock_addr{};
        ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), sizeof(_sock_addr)};

        void _copy_internals(const Address& obj)
        {
            std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
            _addr.addrlen = obj._addr.addrlen;
        }

      public:
        Address() = default;
        explicit Address(std::string addr, uint16_t port);
        explicit Address(uvw::Addr addr) : Address{addr.ip, static_cast<uint16_t>(addr.port)} {};

        Address(const Address& obj) : uvw::Addr{obj} { _copy_internals(obj); }
        Address(Address&& obj) : uvw::Addr{std::move(obj)} { _copy_internals(obj); }

        Address& operator=(const Address& obj)
        {
            uvw::Addr::operator=(obj);
            _copy_internals(obj);
            return *this;
        }
        Address& operator=(Address&& obj)
        {
            uvw::Addr::operator=(std::move(obj));
            _copy_internals(obj);
            return *this;
        }

        // can pass Address object as boolean to check if addr is set
        operator bool() const { return _sock_addr.sin_port; }
        // template code to implicitly convert to uvw::Addr, sockaddr*,
        // sockaddr&, ngtcp2_addr&, and sockaddr_in&
        template <typename T, std::enable_if_t<std::is_same_v<T, sockaddr>, int> = 0>
        operator T*()
        {
            return reinterpret_cast<sockaddr*>(&_sock_addr);
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, sockaddr>, int> = 0>
        operator const T*() const
        {
            return reinterpret_cast<const sockaddr*>(&_sock_addr);
        }
        inline operator sockaddr&() { return reinterpret_cast<sockaddr&>(_sock_addr); }
        inline operator const sockaddr&() const { return reinterpret_cast<const sockaddr&>(_sock_addr); }
        inline operator sockaddr_in&() { return _sock_addr; }
        inline operator const sockaddr_in&() const { return _sock_addr; }
        inline operator ngtcp2_addr&() { return _addr; }
        inline operator const ngtcp2_addr&() const { return _addr; }

        inline bool operator==(const uvw::Addr& other) const { return ip == other.ip && port == other.port; }

        inline ngtcp2_socklen sockaddr_size() const { return sizeof(sockaddr_in); }

        // Convenience method for debugging, etc.
        std::string to_string() const { return fmt::format("{}:{}", ip, port); }
    };

    // Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    // to ngtcp2_path*
    struct Path
    {
      private:
        Address _local, _remote;

        void _update_path()
        {
            path.local = _local;
            path.remote = _remote;
        }

      public:
        ngtcp2_path path{{_local, _local.sockaddr_size()}, {_remote, _remote.sockaddr_size()}, nullptr};

        const Address& local = _local;
        const Address& remote = _remote;

        Path() = default;
        Path(const Address& l, const Address& r) : _local{l}, _remote{r} {}
        Path(const uvw::Addr& l, const uvw::Addr& r) : _local{l}, _remote{r} {}
        Path(const Path& p) : Path{p.local, p.remote} {}
        Path(Path&& p) : Path{std::move(p.local), std::move(p.remote)} {}

        Path& operator=(const Path& p)
        {
            _local = p._local;
            _remote = p._remote;
            _update_path();
            return *this;
        }
        Path& operator=(Path&& p)
        {
            _local = std::move(p._local);
            _remote = std::move(p._remote);
            _update_path();
            return *this;
        }

        // template code to pass Path into ngtcp2 functions
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator T*()
        {
            return &path;
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator const T*() const
        {
            return &path;
        }
    };

    // Simple struct wrapping a packet and its corresponding information
    struct Packet
    {
        Path path;
        bstring_view data;
        ngtcp2_pkt_info pkt_info;
    };

    // Struct returned as a result of send_packet that either is implicitly
    // convertible to bool, but also is able to carry an error code
    struct io_result
    {
        int error_code{0};
        // returns true if this was successful
        operator bool() const { return error_code == 0; }
        // returns true if error value indicates a failure to write
        // without blocking
        bool blocked() const { return error_code == 11; }  // EAGAIN = 11
        // returns error code as string
        std::string_view str() const { return strerror(error_code); }
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

        inline std::string ToString() const
        {
            auto& b = buf;
            std::string out;
            auto ins = std::back_inserter(out);
            fmt::format_to(ins, "Buffer[{}/{:#x} bytes]:", b.size(), b.size());

            for (size_t i = 0; i < b.size(); i += 32)
            {
                fmt::format_to(ins, "\n{:04x} ", i);

                size_t stop = std::min(b.size(), i + 32);
                for (size_t j = 0; j < 32; j++)
                {
                    auto k = i + j;
                    if (j % 4 == 0)
                        out.push_back(' ');
                    if (k >= stop)
                        out.append("  ");
                    else
                        fmt::format_to(ins, "{:02x}", std::to_integer<uint_fast16_t>(b[k]));
                }
                out.append(u8"  ┃");
                for (size_t j = i; j < stop; j++)
                {
                    auto c = std::to_integer<char>(b[j]);
                    if (c == 0x00)
                        out.append(u8"∅");
                    else if (c < 0x20 || c > 0x7e)
                        out.append(u8"·");
                    else
                        out.push_back(c);
                }
                out.append(u8"┃");
            }
            return out;
        };
    };

    template <>
    constexpr inline bool IsToStringFormattable<buffer_printer> = true;

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
            auto h = hash<string>{}(addr.ip);
            h ^= hash<unsigned int>{}(addr.port) + inverse_golden_ratio + (h << 6) + (h >> 2);
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
            return formatter<std::string_view>::format(val.ToString(), ctx);
        }
    };

}  // namespace fmt
