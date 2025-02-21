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
#include <ngtcp2/ngtcp2.h>
}

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <event2/event.h>

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
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

namespace oxen::quic
{
    class connection_interface;

    using time_point = std::chrono::steady_clock::time_point;

    // called when a connection's handshake completes
    // the server will call this when it sends the final handshake packet
    // the client will call this when it receives that final handshake packet
    using connection_established_callback = std::function<void(connection_interface& conn)>;

    // called when a connection closes or times out before the handshake completes
    using connection_closed_callback = std::function<void(connection_interface& conn, uint64_t ec)>;

    using namespace std::literals;
    using namespace oxenc;

    using cspan = std::span<const char>;
    using uspan = std::span<const unsigned char>;
    using bspan = std::span<const std::byte>;

    using stream_buffer = std::deque<std::pair<bspan, std::shared_ptr<void>>>;

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

    inline constexpr size_t inverse_golden_ratio = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

    // NGTCP2 sets the path_pmtud_payload to 1200 on connection creation, then discovers upwards
    // to a theoretical max of 1452. In 'lazy' mode, we take in split packets under the current max
    // pmtud size. In 'greedy' mode, we take in up to double the current pmtud size to split amongst
    // two datagrams. (Note: NGTCP2_MAX_UDP_PAYLOAD_SIZE is badly named, so we're using more accurate
    // ones)

    inline constexpr size_t MIN_UDP_PAYLOAD = NGTCP2_MAX_UDP_PAYLOAD_SIZE;                // 1200
    inline constexpr size_t MIN_LAZY_UDP_PAYLOAD = MIN_UDP_PAYLOAD;                       // 1200
    inline constexpr size_t MIN_GREEDY_UDP_PAYLOAD = (MIN_LAZY_UDP_PAYLOAD << 1);         // 2400
    inline constexpr size_t MAX_PMTUD_UDP_PAYLOAD = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;    // 1452
    inline constexpr size_t MAX_GREEDY_PMTUD_UDP_PAYLOAD = (MAX_PMTUD_UDP_PAYLOAD << 1);  // 2904
                                                                                          //
    // This is the maximum overhead in the UDP packet of sending a packet containing only one single
    // datagram, and is used to determine the maximum datagram size we can send.
    //
    // Specifically this is:
    // + 1 byte for various short packet flags
    // + 20 bytes dcid
    // + 4 bytes (max) packet number
    // + 16 bytes AEAD tag
    // + 1 byte datagram frame type
    // + 2 bytes datagram length.  (This should be optional for the final datagram, but currently ngtcp2 always includes it).
    inline constexpr size_t DATAGRAM_OVERHEAD_1RTT = 1 + 20 + 4 + 16 + 1 + 2;

    // This is the same as DATAGRAM_OVERHEAD_1RTT, but applied in early data (0-RTT) mode.  This is:
    //
    // + 1 byte for various long packet flags
    // + 4 byte version
    // + 1 byte dcid length
    // + 20 bytes dcid
    // + 1 byte dcid length
    // + 20 bytes scid
    // + 2 bytes (max) length
    // + 4 bytes (max) packet number
    // + 1 byte datagram frame type
    // + 2 bytes datagram length.  (As above, should be optional but isn't with current ngtcp2).
    inline constexpr size_t DATAGRAM_OVERHEAD_0RTT = 1 + 4 + 1 + 20 + 1 + 20 + 2 + 4 + 1 + 2;

    // Maximum number of packets we can send in one batch when using sendmmsg/GSO, and maximum we
    // receive in one batch when using recvmmsg.
    inline constexpr size_t DATAGRAM_BATCH_SIZE = 24;

    // Maximum number of packets we will receive at once before returning control to the event loop
    // to re-call the packet receiver if there are additional packets.  (This limit is to prevent
    // loop starvation in the face of heavy incoming packets.).  Note that When using recvmmsg then
    // we can overrun up to the next integer multiple of DATAGRAM_BATCH_SIZE.
    inline constexpr size_t MAX_RECEIVE_PER_LOOP = 64;

    // The minimum size stateless reset packet we will send, as proscribed by section 10.3.3 of the
    // RFC.  Each generated stateless reset packet is smaller than the one that triggered it, down
    // to this limit, to stop a potential infinite loop.
    inline constexpr size_t MIN_STATELESS_RESET_SIZE = 41;

    // Check if T is an instantiation of templated class `Class`; for example,
    // `is_instantiation<std::basic_string, std::string>` is true.
    template <template <typename...> class Class, typename T>
    inline constexpr bool is_instantiation = false;
    template <template <typename...> class Class, typename... Us>
    inline constexpr bool is_instantiation<Class, Class<Us...>> = true;

    std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port = std::nullopt);

    namespace detail
    {
        template <oxenc::basic_char Out, oxenc::basic_char In>
        inline std::span<const Out> to_span(const In* data, size_t datalen)
        {
            return {reinterpret_cast<const Out*>(data), datalen};
        }
    }  // namespace detail

    template <oxenc::string_like T>
    inline bspan str_to_bspan(const T& sv)
    {
        return detail::to_span<std::byte>(sv.data(), sv.size());
    }

    template <oxenc::string_like T>
    inline uspan str_to_uspan(const T& sv)
    {
        return detail::to_span<unsigned char>(sv.data(), sv.size());
    }

    template <oxenc::basic_char Out, oxenc::basic_char In>
    inline std::span<const Out> vec_to_span(const std::vector<In>& v)
    {
        return detail::to_span<Out>(v.data(), v.size());
    }

    template <oxenc::basic_char Out, oxenc::basic_char In>
    inline std::span<const Out> span_to_span(const std::span<const In>& sp)
    {
        return detail::to_span<Out>(sp.data(), sp.size());
    }

    time_point get_time();
    std::chrono::nanoseconds get_timestamp();

    template <typename unit_t>
    auto get_timestamp()
    {
        return std::chrono::duration_cast<unit_t>(get_timestamp());
    }

    std::string str_tolower(std::string s);

    template <std::integral T>
    constexpr bool increment_will_overflow(T val)
    {
        return std::numeric_limits<T>::max() == val;
    }

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

    // Stringview conversion function to interoperate between bstring_views and any other potential
    // user supplied type
    template <oxenc::basic_char CharOut, oxenc::basic_char CharIn>
    std::basic_string_view<CharOut> convert_sv(std::basic_string_view<CharIn> in)
    {
        return {reinterpret_cast<const CharOut*>(in.data()), in.size()};
    }

}  // namespace oxen::quic
