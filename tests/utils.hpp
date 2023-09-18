#pragma once

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <charconv>
#include <future>
#include <optional>
#include <oxen/log.hpp>
#include <quic/endpoint.hpp>
#include <quic/network.hpp>
#include <quic/utils.hpp>
#include <string>

namespace oxen::quic
{
    extern bool disable_ipv6, disable_rotating_buffer;

    inline auto test_cat = oxen::log::Cat("test");

    inline void add_log_opts(CLI::App& cli, std::string& file, std::string& level)
    {
        file = "stderr";
        level = "debug";

        cli.add_option("-l,--log-file", file, "Log output filename, or one of stdout/-/stderr/syslog.")
                ->type_name("FILE")
                ->capture_default_str();

        cli.add_option("-L,--log-level", level, "Log verbosity level; one of trace, debug, info, warn, error, critical, off")
                ->type_name("LEVEL")
                ->capture_default_str()
                ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "critical", "off"}));
    }

    inline void setup_logging(std::string out, const std::string& level)
    {
        log::Level lvl = log::level_from_string(level);

        constexpr std::array print_vals = {"stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
        log::Type type;
        if (std::count(print_vals.begin(), print_vals.end(), out))
            type = log::Type::Print;
        else if (out == "syslog")
            type = log::Type::System;
        else
            type = log::Type::File;

        logger_config(out, type, lvl);
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

    inline std::pair<std::string, uint16_t> parse_addr(
            std::string_view addr, std::optional<uint16_t> default_port = std::nullopt)
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

    template <typename F>
    void require_future(F& f, std::chrono::milliseconds timeout = 1s)
    {
        REQUIRE(f.wait_for(timeout) == std::future_status::ready);
    }

    template <typename T>
    struct functional_helper : public functional_helper<decltype(&T::operator())>
    {};

    template <typename Class, typename Ret, typename... Args>
    struct functional_helper<Ret (Class::*)(Args...) const>
    {
        using type = std::function<Ret(Args...)>;
    };

    template <typename T>
    using functional_helper_t = typename functional_helper<T>::type;

    template <typename T>
    struct bool_waiter
    {
        using Func_t = functional_helper_t<T>;

        Func_t func;
        std::promise<bool> p;
        std::future<bool> f{p.get_future()};

        explicit bool_waiter(T f) : func{std::move(f)} {}

        bool wait_ready(std::chrono::milliseconds timeout = 1s) { return f.wait_for(timeout) == std::future_status::ready; }

        bool is_ready() { return f.wait_for(0s) == std::future_status::ready; }

        bool get() { return f.get(); }

        // Deliberate implicit conversion to the std::function<...>
        operator Func_t()
        {
            return [this](auto&&... args) {
                p.set_value(true);
                return func(std::forward<decltype(args)>(args)...);
            };
            return func;
        }
    };

}  // namespace oxen::quic
