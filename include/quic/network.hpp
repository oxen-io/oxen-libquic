#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <uvw.hpp>

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
        using handle_address_pair = std::pair<const Address, std::shared_ptr<uv_udp_t>>;

      public:
        Network(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id thread_id);
        Network();
        ~Network();

        std::shared_ptr<Endpoint> endpoint(const Address& local_addr);

        void close();

      private:
        std::atomic<bool> running{false};
        std::shared_ptr<uvw::loop> ev_loop;
        std::unique_ptr<std::thread> loop_thread;

        // Maps local listening address to respective endpoint
        std::unordered_map<Address, std::shared_ptr<Endpoint>> endpoint_map;
        std::unordered_map<Address, std::shared_ptr<uv_udp_t>> handle_map;

        std::shared_ptr<uv_udp_t> map_udp_handle(const Address& local, Endpoint& ep);

        std::shared_ptr<uv_udp_t> start_udp_handle(uv_loop_t* loop, const Address& bind, Endpoint& ep);

        std::thread::id loop_thread_id;
        std::shared_ptr<uvw::async_handle> job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

      protected:
        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        std::shared_ptr<uvw::loop> loop();

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

        void close_all();
    };
}  // namespace oxen::quic
