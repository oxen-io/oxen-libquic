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

        std::shared_ptr<Endpoint> endpoint(const Address& local_addr);

        /// Initiates shutdown the network, closing all endpoint connections and stopping the event
        /// loop (if Network-managed).  If graceful is true (the default) this call initiates a
        /// graceful shutdown (sending connection close packets, etc.).
        ///
        /// Returns a future that can be waited on to block until a graceful shutdown complete (for
        /// ungraceful, the promise will be available immediately).
        std::future<void> close(bool graceful = true);

      private:
        std::atomic<bool> running{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        std::unordered_map<Address, std::shared_ptr<Endpoint>> endpoint_map;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        void setup_job_waker();

        bool in_event_loop() const;

        void call_soon(std::function<void(void)> f, source_location src = source_location::current());

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

        void process_job_queue();

        // Asynchronously begins closing (e.g. sending close packets) for all endpoints.  Triggers a
        // call to `close_ungraceful` when all connections have had their close packet written.  If
        // the promise is given, it will be passed on to `close_final()` to be fulfilled once
        // closing is complete.
        void close_all(std::shared_ptr<std::promise<void>> done = nullptr);

        void close_final(std::shared_ptr<std::promise<void>> done = nullptr);
    };
}  // namespace oxen::quic
