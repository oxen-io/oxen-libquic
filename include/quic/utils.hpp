#pragma once

#include "format.hpp"

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <event2/event.h>
#include <fmt/core.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <cassert>
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
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    using namespace std::literals;
    using namespace oxen::log::literals;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;
    using stream_buffer = std::deque<std::pair<bstring_view, std::shared_ptr<void>>>;
    namespace log = oxen::log;

    constexpr bool IN_HELL =
#ifdef _WIN32
            true;
#else
            false;
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

    inline constexpr int DEFAULT_MAX_BIDI_STREAMS = 32;

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

    // Application error code we close with if the stream data handle throws
    inline constexpr uint64_t STREAM_ERROR_EXCEPTION = (1ULL << 62) - 2;
    // Application error code we close with if the datagram data handle throws
    inline constexpr uint64_t DATAGRAM_ERROR_EXCEPTION = (1ULL << 62) - 32;
    // Error code we send to a stream close callback if the stream's connection expires
    inline constexpr uint64_t STREAM_ERROR_CONNECTION_EXPIRED = (1ULL << 62) + 1;

    // bstring_view literals baby
    inline std::basic_string_view<std::byte> operator""_bsv(const char* __str, size_t __len) noexcept
    {
        return std::basic_string_view<std::byte>(reinterpret_cast<const std::byte*>(__str), __len);
    }

    void logger_config(std::string out = "stderr", log::Type type = log::Type::Print, log::Level reset = log::Level::trace);

    std::chrono::steady_clock::time_point get_time();
    std::chrono::nanoseconds get_timestamp();

    std::string str_tolower(std::string s);

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

    struct event_deleter final
    {
        void operator()(::event* e) const
        {
            if (e)
                ::event_free(e);
        }
    };
    using event_ptr = std::unique_ptr<::event, event_deleter>;

    // Stringview conversion function to interoperate between bstring_views and any other potential
    // user supplied type
    template <typename CharOut, typename CharIn, typename = std::enable_if_t<sizeof(CharOut) == 1 && sizeof(CharIn) == 1>>
    std::basic_string_view<CharOut> convert_sv(std::basic_string_view<CharIn> in)
    {
        return {reinterpret_cast<const CharOut*>(in.data()), in.size()};
    }
}  // namespace oxen::quic
