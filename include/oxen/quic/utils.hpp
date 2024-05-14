#pragma once

#include <type_traits>

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
}

#include <event2/event.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <future>
#include <iostream>
#include <list>
#include <map>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

namespace oxen::quic
{
    class connection_interface;

    // called when a connection's handshake completes
    // the server will call this when it sends the final handshake packet
    // the client will call this when it receives that final handshake packet
    using connection_established_callback = std::function<void(connection_interface& conn)>;

    // called when a connection closes or times out before the handshake completes
    using connection_closed_callback = std::function<void(connection_interface& conn, uint64_t ec)>;

    using namespace std::literals;
    using bstring = std::basic_string<std::byte>;
    using ustring = std::basic_string<unsigned char>;
    using bstring_view = std::basic_string_view<std::byte>;
    using ustring_view = std::basic_string_view<unsigned char>;
    using stream_buffer = std::deque<std::pair<bstring_view, std::shared_ptr<void>>>;

#ifdef _WIN32
    inline constexpr bool IN_HELL = true;
    extern const bool EMULATING_HELL;  // True if compiled for windows but running under WINE
#else
    inline constexpr bool IN_HELL = false;
    inline constexpr bool EMULATING_HELL = false;
#endif

    struct ngtcp2_error_code_t final
    {};

    // Tag value to pass into the io_result/io_error constructors to indicate an ngtcp2 error code.
    // (For ngtcp2, error codes are arbitrary negative values without any connection to errno).
    static inline constexpr ngtcp2_error_code_t ngtcp2_error_code{};

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

    inline constexpr uint64_t DEFAULT_MAX_BIDI_STREAMS = 32;

    inline constexpr std::chrono::seconds DEFAULT_HANDSHAKE_TIMEOUT = 10s;
    inline constexpr std::chrono::seconds DEFAULT_IDLE_TIMEOUT = 30s;

    // NGTCP2 sets the path_pmtud_payload to 1200 on connection creation, then discovers upwards
    // to a theoretical max of 1452. In 'lazy' mode, we take in split packets under the current max
    // pmtud size. In 'greedy' mode, we take in up to double the current pmtud size to split amongst
    // two datagrams. (Note: NGTCP2_MAX_UDP_PAYLOAD_SIZE is badly named, so we're using more accurate
    // ones)
    inline constexpr size_t DATAGRAM_OVERHEAD = 44;
    inline constexpr size_t MIN_UDP_PAYLOAD = NGTCP2_MAX_UDP_PAYLOAD_SIZE;                // 1200
    inline constexpr size_t MIN_LAZY_UDP_PAYLOAD = MIN_UDP_PAYLOAD;                       // 1200
    inline constexpr size_t MIN_GREEDY_UDP_PAYLOAD = (MIN_LAZY_UDP_PAYLOAD << 1);         // 2400
    inline constexpr size_t MAX_PMTUD_UDP_PAYLOAD = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;    // 1452
    inline constexpr size_t MAX_GREEDY_PMTUD_UDP_PAYLOAD = (MAX_PMTUD_UDP_PAYLOAD << 1);  // 2904

    // Maximum number of packets we can send in one batch when using sendmmsg/GSO, and maximum we
    // receive in one batch when using recvmmsg.
    inline constexpr size_t DATAGRAM_BATCH_SIZE = 24;

    // Maximum number of packets we will receive at once before returning control to the event loop
    // to re-call the packet receiver if there are additional packets.  (This limit is to prevent
    // loop starvation in the face of heavy incoming packets.).  Note that When using recvmmsg then
    // we can overrun up to the next integer multiple of DATAGRAM_BATCH_SIZE.
    inline constexpr size_t MAX_RECEIVE_PER_LOOP = 64;

    // Check if T is an instantiation of templated class `Class`; for example,
    // `is_instantiation<std::basic_string, std::string>` is true.
    template <template <typename...> class Class, typename T>
    inline constexpr bool is_instantiation = false;
    template <template <typename...> class Class, typename... Us>
    inline constexpr bool is_instantiation<Class, Class<Us...>> = true;

    std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port = std::nullopt);

    namespace detail
    {
        template <size_t N>
        struct bsv_literal
        {
            consteval bsv_literal(const char (&s)[N])
            {
                for (size_t i = 0; i < N; i++)
                    str[i] = static_cast<std::byte>(s[i]);
            }
            std::byte str[N];  // we keep the null on the end, in case you pass .data() to a C func
            using size = std::integral_constant<size_t, N - 1>;
        };
        template <size_t N>
        struct usv_literal
        {
            consteval usv_literal(const char (&s)[N])
            {
                for (size_t i = 0; i < N; i++)
                    str[i] = static_cast<unsigned char>(s[i]);
            }
            unsigned char str[N];  // we keep the null on the end, in case you pass .data() to a C func
            using size = std::integral_constant<size_t, N - 1>;
        };
    }  // namespace detail

    // strang literals
    inline ustring operator""_us(const char* str, size_t len) noexcept
    {
        return {reinterpret_cast<const unsigned char*>(str), len};
    }
    template <detail::usv_literal UStr>
    constexpr ustring_view operator""_usv()
    {
        return {UStr.str, decltype(UStr)::size::value};
    }

    template <detail::bsv_literal BStr>
    constexpr bstring_view operator""_bsv()
    {
        return {BStr.str, decltype(BStr)::size::value};
    }
    inline bstring operator""_bs(const char* str, size_t len) noexcept
    {
        return {reinterpret_cast<const std::byte*>(str), len};
    }

    template <typename SV>
        requires std::same_as<SV, ustring_view> || std::same_as<SV, bstring_view>
    inline std::string_view to_sv(SV x)
    {
        return {reinterpret_cast<const char*>(x.data()), x.size()};
    }

    std::chrono::steady_clock::time_point get_time();
    std::chrono::nanoseconds get_timestamp();

    std::string str_tolower(std::string s);

    /// Parses an integer of some sort from a string, requiring that the entire string be consumed
    /// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
    /// string was consumed.
    template <typename T>
    bool parse_int(const std::string_view str, T& value, int base = 10)
    {
        T tmp;
        auto* strend = str.data() + str.size();
        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
        if (ec != std::errc() || p != strend)
            return false;
        value = tmp;
        return true;
    }

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    int check_rv(int rv, std::string_view action);

    // Shortcut for a const-preserving `reinterpret_cast`ing c.data() from a std::byte to a uint8_t
    // pointer, because we need it all over the place in the ngtcp2 API
    template <typename Container>
        requires(sizeof(typename std::remove_reference_t<Container>::value_type) == sizeof(uint8_t))
    auto* u8data(Container&& c)
    {
        using u8_sameconst_t =
                std::conditional_t<std::is_const_v<std::remove_pointer_t<decltype(c.data())>>, const uint8_t, uint8_t>;
        return reinterpret_cast<u8_sameconst_t*>(c.data());
    }

    struct event_deleter final
    {
        void operator()(::event* e) const;
    };
    using event_ptr = std::unique_ptr<::event, event_deleter>;

    inline ustring_view to_usv(std::string_view sv)
    {
        return {reinterpret_cast<const unsigned char*>(sv.data()), sv.size()};
    }

    // Stringview conversion function to interoperate between bstring_views and any other potential
    // user supplied type
    template <oxenc::basic_char CharOut, oxenc::basic_char CharIn>
    std::basic_string_view<CharOut> convert_sv(std::basic_string_view<CharIn> in)
    {
        return {reinterpret_cast<const CharOut*>(in.data()), in.size()};
    }

}  // namespace oxen::quic
