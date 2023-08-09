#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <event2/event.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

using oxen::log::slns::source_location;

namespace oxen::quic
{
    template <typename... T>
    void loop_trace_log(
            const log::logger_ptr& cat_logger,
            [[maybe_unused]] const source_location& location,
            [[maybe_unused]] fmt::format_string<T...> fmt,
            [[maybe_unused]] T&&... args)
    {
#if defined(NDEBUG) && !defined(OXEN_LOGGING_RELEASE_TRACE)
        // Using [[maybe_unused]] on the *first* ctor argument breaks gcc 8/9
        (void)cat_logger;
#else
        if (cat_logger)
            cat_logger->log(log::detail::spdlog_sloc(location), log::Level::trace, fmt, std::forward<T>(args)...);
#endif
    }

    class Endpoint;

    class Network
    {
        using Job = std::pair<std::function<void()>, source_location>;

      public:
        Network(std::shared_ptr<::event_base> loop_ptr, std::thread::id loop_thread_id);
        Network();
        ~Network();

        template <typename... Opt>
        std::shared_ptr<Endpoint> endpoint(const Address& local_addr, Opt&&... opts)
        {
            auto [it, added] =
                    endpoint_map.emplace(std::make_shared<Endpoint>(*this, local_addr, std::forward<Opt>(opts)...));

            return *it;
        }

        void set_shutdown_immediate(bool b = true) { shutdown_immediate = b; }

      private:
        std::atomic<bool> running{false};
        std::atomic<bool> shutdown_immediate{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        std::unordered_set<std::shared_ptr<Endpoint>> endpoint_map;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        void setup_job_waker();

        bool in_event_loop() const;

        /// Posts a function to the event loop, to be called when the event loop is next free.
        void call_soon(std::function<void()> f, source_location src = source_location::current());

        /// Calls a function: if this is called from within the event loop thread, the function is
        /// called immediately; otherwise it is forwarded to `call_soon`.
        template <typename Callable>
        void call(Callable&& f, source_location src = source_location::current())
        {
            if (in_event_loop())
            {
                loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f), std::move(src));
            }
        }

        /// Calls a function and synchronously obtains its return value.  If called from within the
        /// event loop, the function is called and returned immediately, otherwise a promise/future
        /// is used with `call_soon` to block until the event loop comes around and calls the
        /// function.
        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f, source_location src = source_location::current())
        {
            if (in_event_loop())
            {
                loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
                return f();
            }

            std::promise<Ret> prom;
            auto fut = prom.get_future();
            call_soon([&f, &prom] { prom.set_value(f()); });
            return fut.get();
        }

        void process_job_queue();

        void close_gracefully();

        void close_immediate();
    };
}  // namespace oxen::quic
