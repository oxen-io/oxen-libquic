#include "utils.hpp"

#include <oxenc/endian.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>

#include "connection.hpp"
#include "internal.hpp"

namespace oxen::quic
{
    void logger_config(std::string out, log::Type type, log::Level reset)
    {
        static std::atomic<bool> run_once{false};

        if (not run_once.exchange(true))
        {
            oxen::log::add_sink(type, out);
            oxen::log::reset_level(reset);
        }
    }

    std::chrono::steady_clock::time_point get_time()
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

    static auto ev_cat = log::Cat("ev-loop");

    static void setup_libevent_logging()
    {
        event_set_log_callback([](int severity, const char* msg) {
            switch (severity)
            {
                case _EVENT_LOG_ERR:
                    log::error(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_WARN:
                    log::warning(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_MSG:
                    log::info(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_DEBUG:
                    log::debug(ev_cat, "{}", msg);
                    break;
            }
            std::abort();
        });
    }
}  // namespace oxen::quic
