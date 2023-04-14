#pragma once

#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>

#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gnutls/gnutls.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>

// temporary placeholders
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 4433
#define ALPN "dummy"
#define MESSAGE "GET /\r\n"

/*
 * Example 1: Handshake with www.google.com
 *
 * #define REMOTE_HOST "www.google.com"
 * #define REMOTE_PORT "443"
 * #define ALPN "\x2h3"
 *
 * and undefine MESSAGE macro.
 */

namespace oxen::quic
{
    using namespace std::literals;
    using bstring = std::basic_string<std::byte>;

    static constexpr std::byte CLIENT_TO_SERVER{1};
    static constexpr std::byte SERVER_TO_CLIENT{2};
    static constexpr size_t dgram_size = 1200;

    static constexpr size_t ev_loop_queue_size = 1024;

    // Max theoretical size of a UDP packet is 2^16-1 minus IP/UDP header overhead
    static constexpr size_t max_bufsize = 64 * 1024;
    // Max size of a UDP packet that we'll send
    static constexpr size_t max_pkt_size_v4 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
    static constexpr size_t max_pkt_size_v6 = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

    // Remote TCP connection was established and is now accepting stream data; the client is not allowed 
    // to send any other data down the stream until this comes back (any data sent down the stream before 
    // then is discarded)
    static constexpr std::byte CONNECT_INIT{0x00};
    // Failure to establish an initial connection:
    static constexpr uint64_t ERROR_CONNECT{0x5471907};
    // Error for something other than CONNECT_INIT as the initial stream data from the server
    static constexpr uint64_t ERROR_BAD_INIT{0x5471908};
    // Close error code sent if we get an error on the TCP socket (other than an initial connect failure)
    static constexpr uint64_t ERROR_TCP{0x5471909};

    // We pause reading from the local TCP socket if we have more than this amount of outstanding
    // unacked data in the quic tunnel, then resume once it drops below this.
    inline constexpr size_t PAUSE_SIZE = 64 * 1024;

    const char priority[] =
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
        "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
        "+GROUP-SECP384R1:"
        "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

    const gnutls_datum_t alpn = {(uint8_t *)ALPN, sizeof(ALPN) - 1};

    static uint64_t
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

    static std::string
    str_tolower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        return s;
    }

    //  Wrapper for ngtcp2_addr with helper functionalities, sockaddr_in6, etc
    struct Address
    {
        private:
            sockaddr_in6 _sock_addr{};
            ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), sizeof(_sock_addr)};

        public:
            Address() = default;
            Address(std::string addr, uint16_t port) 
            {
                memset(&_sock_addr, 0, sizeof(_sock_addr));
                _sock_addr.sin6_family = AF_INET6;
                _sock_addr.sin6_port = port;

                if (auto rv = inet_pton(AF_INET6, addr.c_str(), &_sock_addr.sin6_addr); rv != 1)
                {
                    throw std::runtime_error("Erorr: could not parse IPv6 address from string");
                }
            }
            Address(const sockaddr_in6& addr) : _sock_addr{addr} {}
            Address(const sockaddr_in6& addr, uint16_t port) : _sock_addr{addr} 
            { _sock_addr.sin6_port = port; }

            Address(const Address& obj) { *this = obj; }
            inline Address& operator=(const Address& obj)
            {
                std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
                _addr.addrlen = obj._addr.addrlen;
                return *this;
            }

            // can pass Address object as boolean to check if addr is set
            operator bool() const { return _sock_addr.sin6_port; }

            //  template code to implicitly convert to sockaddr*, sockaddr&, ngtcp2_addr&, and sockaddr_in6&
            template <typename T, std::enable_if_t<std::is_same_v<T, sockaddr>, int> = 0>
            operator T*()
            { return reinterpret_cast<sockaddr*>(&_sock_addr); }
            template <typename T, std::enable_if_t<std::is_same_v<T, sockaddr>, int> = 0>
            operator const T*() const
            { return reinterpret_cast<const sockaddr*>(&_sock_addr); }
            inline operator
            sockaddr&() { return reinterpret_cast<sockaddr&>(_sock_addr); }
            inline operator const
            sockaddr&() const { return reinterpret_cast<const sockaddr&>(_sock_addr); }
            inline operator
            sockaddr_in6&() { return _sock_addr; }
            inline operator const
            sockaddr_in6&() const { return _sock_addr; }
            inline operator 
            ngtcp2_addr&() { return _addr; }
            inline operator const 
            ngtcp2_addr&() const { return _addr; }

            inline ngtcp2_socklen 
            sockaddr_size() const { return sizeof(sockaddr_in6); }

            inline uint16_t
            port() const { return _sock_addr.sin6_port; }

            inline void 
            port(uint16_t port) { _sock_addr.sin6_port = port; }
    };

    //  Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    //  to ngtcp2_path*
    struct Path
    {
        private:
            Address _local, _remote;

        public:
            ngtcp2_path path{ 
                {_local, _local.sockaddr_size()}, {_remote, _remote.sockaddr_size()}, nullptr};

            const Address& local = _local;
            const Address& remote = _remote;
            
            Path() = default;
            Path(const Address& l, const Address& r) : _local{l}, _remote{r} {}
            Path(const Path& p) : Path{p.local, p.remote} {}

            Path& operator=(const Path& p)
            {
                _local = p._local;
                _remote = p._remote;
                return *this;
            }

            // template code to pass Path into ngtcp2 functions
            template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
            operator T*() { return &path; }
            template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
            operator const T*() const { return &path; }
    };

    //  Simple struct wrapping a packet and its corresponding information
    struct Packet
    {
        Path path;
        bstring data;
        ngtcp2_pkt_info pkt_info;
    };

    //  Struct returned as a result of send_packet that either is implicitly
    //  convertible to bool, but also is able to carry an error code
    struct io_result
    {
        int error_code{0};
        // returns true if this was successful
        operator bool() const { return error_code == 0; }
        //  returns true if error value indicates a failure to write
        //  without blocking
        bool blocked() const { return error_code == 11; } // EAGAIN = 11
        // returns error code as string
        std::string_view str() const { return strerror(error_code); }
    };

    // Shortcut for a const-preserving `reinterpret_cast`ing c.data() from a std::byte to a uint8_t
    // pointer, because we need it all over the place in the ngtcp2 API
    template <
        typename Container,
        typename = std::enable_if_t<
            sizeof(typename std::remove_reference_t<Container>::value_type) == sizeof(uint8_t)>>
    inline auto*
    u8data(Container&& c)
    {
        using u8_sameconst_t = std::conditional_t<
            std::is_const_v<std::remove_pointer_t<decltype(c.data())>>,
            const uint8_t,
            uint8_t>;
        return reinterpret_cast<u8_sameconst_t*>(c.data());
    }

}   // namespace oxen::quic
