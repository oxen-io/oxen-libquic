#pragma once

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <charconv>
#include <future>
#include <optional>
#include <oxen/log.hpp>
#include <quic/network.hpp>
#include <quic/utils.hpp>
#include <string>

namespace oxen::quic
{
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

        result.first = addr;
        return result;
    }

    // Runs the `net` event loop in a new thread; returns the thread and a pair of futures: the
    // first future is set when the event loop is up and running (after one non-blocking tick); the
    // second is set when the event loop finishes.
    inline std::tuple<std::thread, std::future<void>, std::future<void>> spawn_event_loop(Network& net)
    {
        std::promise<void> running, done;
        auto running_fut = running.get_future(), done_fut = done.get_future();
        std::thread ev_thread{[&net, running = std::move(running), done = std::move(done)]() mutable {
            // Run once (non-blocking) to be sure we are up and running before fulfilling the future
            net.ev_loop->run<uvw::Loop::Mode::NOWAIT>();
            running.set_value();
            net.run();
            done.set_value();
        }};

        return {std::move(ev_thread), std::move(running_fut), std::move(done_fut)};
    }

}  // namespace oxen::quic
