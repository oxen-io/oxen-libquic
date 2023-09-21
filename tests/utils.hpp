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
        using return_type = Ret;
        static constexpr bool is_void = std::is_void_v<Ret>;
        using type = std::function<Ret(Args...)>;
    };

    template <typename T>
    using functional_helper_t = typename functional_helper<T>::type;

    struct set_on_exit
    {
        std::promise<void>& p;
        explicit set_on_exit(std::promise<void>& p) : p{p} {}
        ~set_on_exit() { p.set_value(); }
    };

    /// Test suite helper that takes a callable lambda at construction and then man-in-the-middles
    /// an intermediate std::function matching the lambda that calls the inner lambda but also sets
    /// a promise just after calling the inner lambda.
    ///
    /// The main purpose is to synchronize an asynchronous interface with a promise/future to
    /// simplify test code which is full of "wait for this thing to be called" checks, without
    /// needing any sort of sleep & poll (and reducing the direct usage of promise/futures in the
    /// test suite).
    ///
    /// Usage example:
    ///
    ///     int foo = 0;
    ///     callback_waiter waiter{[&foo](int a, int b) { foo = a + b; }};
    ///     invoke_something(waiter);
    ///
    /// where `invoke_something` takes a `std::function<int(Foo&, int)>`.  The test code would then
    /// go on to synchronize with:
    ///
    ///     REQUIRE(waiter.wait(/* 1s */)); // will fail if the lambda doesn't get called within ~1s
    ///
    /// and then can go on to check side effects of the lambda, e.g.:
    ///
    ///     CHECK(foo == 42);
    ///
    /// Care must be taken to ensure the lambda is only called once.  The lambda may throw, but the
    /// throw propagates to the caller of the lambda, *not* the inner promise.
    template <typename T>
    struct callback_waiter
    {
        using Func_t = functional_helper_t<T>;

        Func_t func;
        std::promise<void> p;
        std::future<void> f{p.get_future()};

        explicit callback_waiter(T f) : func{std::move(f)} {}

        bool wait(std::chrono::milliseconds timeout = 1s) { return f.wait_for(timeout) == std::future_status::ready; }

        bool is_ready() { return wait(0s); }

        // Deliberate implicit conversion to the std::function<...>
        operator Func_t()
        {
            return [this](auto&&... args) {
                set_on_exit prom_setter{p};
                return func(std::forward<decltype(args)>(args)...);
            };
        }
    };

}  // namespace oxen::quic
