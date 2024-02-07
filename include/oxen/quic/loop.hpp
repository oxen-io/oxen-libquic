#pragma once

#include <event2/event.h>
#include <event2/thread.h>

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
    static auto ev_cat = log::Cat("libevent");

    using Job = std::pair<std::function<void()>, source_location>;

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

    class Loop
    {
      protected:
        std::atomic<bool> running{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

      public:
        Loop(std::shared_ptr<::event_base> loop_ptr, std::thread::id thread_id) :
                ev_loop{std::move(loop_ptr)}, loop_thread_id{thread_id}
        {
            assert(ev_loop);
            log::trace(log_cat, "Beginning event loop creation with pre-existing ev loop thread");

            setup_job_waker();

            running.store(true);
        }

        Loop()
        {
            log::trace(log_cat, "Beginning loop context creation with new ev loop thread");

#ifdef _WIN32
            {
                WSADATA ignored;
                if (int err = WSAStartup(MAKEWORD(2, 2), &ignored); err != 0)
                {
                    log::critical(log_cat, "WSAStartup failed to initialize the windows socket layer ({0x:x})", err);
                    throw std::runtime_error{"Unable to initialize windows socket layer"};
                }
            }
#endif

            if (static bool once = false; !once)
            {
                once = true;
                setup_libevent_logging();

                // Older versions of libevent do not like having this called multiple times
#ifdef _WIN32
                evthread_use_windows_threads();
#else
                evthread_use_pthreads();
#endif
            }

            std::vector<std::string_view> ev_methods_avail;
            for (const char** methods = event_get_supported_methods(); *methods != nullptr; methods++)
                ev_methods_avail.push_back(*methods);
            log::debug(
                    log_cat,
                    "Starting libevent {}; available backends: {}",
                    event_get_version(),
                    "{}"_format(fmt::join(ev_methods_avail, ", ")));

            std::unique_ptr<event_config, decltype(&event_config_free)> ev_conf{event_config_new(), event_config_free};
            event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_PRECISE_TIMER);
            event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

            ev_loop = std::shared_ptr<event_base>{event_base_new_with_config(ev_conf.get()), event_base_free};

            log::info(log_cat, "Started libevent loop with backend {}", event_base_get_method(ev_loop.get()));

            setup_job_waker();

            std::promise<void> p;

            loop_thread.emplace([this, &p]() mutable {
                log::debug(log_cat, "Starting event loop run");
                p.set_value();
                event_base_loop(ev_loop.get(), EVLOOP_NO_EXIT_ON_EMPTY);
                log::debug(log_cat, "Event loop run returned, thread finished");
            });

            loop_thread_id = loop_thread->get_id();
            p.get_future().get();

            running.store(true);
            log::info(log_cat, "loop is started");
        }

        virtual ~Loop()
        {
            log::info(log_cat, "Shutting down loop...");

            if (loop_thread)
                event_base_loopbreak(ev_loop.get());

            if (loop_thread and loop_thread->joinable())
                loop_thread->join();

            log::info(log_cat, "Loop shutdown complete");

#ifdef _WIN32
            if (loop_thread)
                WSACleanup();
#endif
        }

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        bool in_event_loop() const { return std::this_thread::get_id() == loop_thread_id; }

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call([ptr] { delete ptr; }); };
        }

        // Similar in concept to std::make_shared<T>, but it creates the shared pointer with a
        // custom deleter that dispatches actual object destruction to the network's event loop for
        // thread safety.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::shared_ptr<T>{ptr, loop_deleter<T>()};
        }

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

            call_soon([&f, &prom] {
                try
                {
                    if constexpr (!std::is_void_v<Ret>)
                        prom.set_value(f());
                    else
                    {
                        f();
                        prom.set_value();
                    }
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });

            return fut.get();
        }

        void call_soon(std::function<void(void)> f, source_location src = source_location::current())
        {
            loop_trace_log(log_cat, src, "Event loop queueing `{}`", src.function_name());
            {
                std::lock_guard lock{job_queue_mutex};
                job_queue.emplace(std::move(f), std::move(src));
                log::trace(log_cat, "Event loop now has {} jobs queued", job_queue.size());
            }

            event_active(job_waker.get(), 0, 0);
        }

        void shutdown(bool immediate = false)
        {
            log::info(log_cat, "Shutting down loop...");

            if (loop_thread)
                immediate ? event_base_loopbreak(ev_loop.get()) : event_base_loopexit(ev_loop.get(), nullptr);

            if (loop_thread and loop_thread->joinable())
                loop_thread->join();

            log::info(log_cat, "Loop shutdown complete");

#ifdef _WIN32
            if (loop_thread)
                WSACleanup();
#endif
        }

      private:
        void setup_job_waker()
        {
            job_waker.reset(event_new(
                    ev_loop.get(),
                    -1,
                    0,
                    [](evutil_socket_t, short, void* self) {
                        log::trace(log_cat, "processing job queue");
                        static_cast<Loop*>(self)->process_job_queue();
                    },
                    this));
            assert(job_waker);
        }

        void process_job_queue()
        {
            log::trace(log_cat, "Event loop processing job queue");
            assert(in_event_loop());

            decltype(job_queue) swapped_queue;

            {
                std::lock_guard<std::mutex> lock{job_queue_mutex};
                job_queue.swap(swapped_queue);
            }

            while (not swapped_queue.empty())
            {
                auto job = swapped_queue.front();
                swapped_queue.pop();
                const auto& src = job.second;
                loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
                job.first();
            }
        }
    };
}  //  namespace oxen::quic
