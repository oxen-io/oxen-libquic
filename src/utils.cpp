#include "utils.hpp"

#include <oxenc/endian.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>

#include "connection.hpp"
#include "internal.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

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

    int check_rv(int rv, std::string_view action)
    {
        std::optional<std::error_code> ec;
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            ec.emplace(WSAGetLastError(), std::system_category());
#else
        if (rv == -1)
            ec.emplace(errno, std::system_category());

#endif
        if (ec)
        {
            log::error(log_cat, "Got error {} ({}) during {}", ec->value(), ec->message(), action);
            throw std::system_error{*ec};
        }

        return rv;
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

    std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port)
    {
        std::pair<std::string, uint16_t> result;
        if (auto p = addr.find_last_not_of("0123456789");
            p != std::string_view::npos && p + 2 <= addr.size() && addr[p] == ':')
        {
            if (!parse_int(addr.substr(p + 1), result.second))
                throw std::invalid_argument{"Invalid address: could not parse port"};
            addr.remove_suffix(addr.size() - p);
        }
        else if (default_port)
        {
            result.second = *default_port;
        }
        else
        {
            throw std::invalid_argument{"Invalid address: no port was specified and there is no default"};
        }

        bool had_sq_brackets = false;
        if (!addr.empty() && addr.front() == '[' && addr.back() == ']')
        {
            addr.remove_prefix(1);
            addr.remove_suffix(1);
            had_sq_brackets = true;
        }

        if (auto p = addr.find_first_not_of("0123456789."); p != std::string_view::npos)
        {
            if (auto q = addr.find_first_not_of("0123456789abcdef:."); q != std::string_view::npos)
                throw std::invalid_argument{"Invalid address: does not look like IPv4 or IPv6!"};
            else if (!had_sq_brackets)
                throw std::invalid_argument{"Invalid address: IPv6 addresses require [...] square brackets"};
        }

        if (addr.empty())
            addr = "::";

        result.first = addr;
        return result;
    }

#ifdef _WIN32
    static bool running_under_wine_impl()
    {
        auto ntdll = GetModuleHandle("ntdll.dll");
        return ntdll && GetProcAddress(ntdll, "wine_get_version");
    }
    const bool EMULATING_HELL = running_under_wine_impl();
#endif

}  // namespace oxen::quic
