#include "utils.hpp"

#include <oxenc/endian.h>

#include <event2/event.h>
#include <ngtcp2/ngtcp2.h>

#include <chrono>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace oxen::quic
{
    time_point get_time()
    {
        return std::chrono::steady_clock::now();
    }
    std::chrono::nanoseconds get_timestamp()
    {
        return std::chrono::steady_clock::now().time_since_epoch();
    }

    std::string str_tolower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    void event_deleter::operator()(::event* e) const
    {
        if (e)
            ::event_free(e);
    }

    // We hard-code these constants in utils.hpp to avoid needing to include all of ngtcp2, but
    // verify here that they match the ngtcp2 value.
    static_assert(MIN_UDP_PAYLOAD == NGTCP2_MAX_UDP_PAYLOAD_SIZE);
    static_assert(MAX_PMTUD_UDP_PAYLOAD == NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE);

#ifdef _WIN32
    static bool running_under_wine_impl()
    {
        auto ntdll = GetModuleHandle("ntdll.dll");
        return ntdll && GetProcAddress(ntdll, "wine_get_version");
    }
    const bool EMULATING_HELL = running_under_wine_impl();
#endif

}  // namespace oxen::quic
