#pragma once

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
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    using namespace std::literals;
    using namespace oxen::log::literals;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;
    namespace log = oxen::log;

    constexpr bool IN_HELL =
#ifdef _WIN32
            true;
#else
            false;
#endif

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

    // Max payload size of a UDP packet that we'll send
    inline constexpr size_t max_payload_size = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;

    // Application error code we close with if the data handle throws
    inline constexpr uint64_t STREAM_ERROR_EXCEPTION = (1ULL << 62) - 2;
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
