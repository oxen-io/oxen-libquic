#include "network.hpp"

#include <event2/event.h>
#include <event2/thread.h>

#include <exception>
#include <memory>
#include <oxen/log.hpp>
#include <stdexcept>
#include <string_view>
#include <thread>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    static auto ev_cat = log::Cat("libevent");
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

    Network::Network(std::shared_ptr<event_base> loop_ptr, std::thread::id thread_id) :
            ev_loop{std::move(loop_ptr)}, loop_thread_id{thread_id}
    {
        assert(ev_loop);
        log::trace(log_cat, "Beginning network context creation with pre-existing ev loop thread");

        setup_job_waker();

        running.store(true);
    }

    Network::Network()
    {
        log::trace(log_cat, "Beginning network context creation with new ev loop thread");

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
        log::info(log_cat, "Network is started");
    }

    Network::~Network()
    {
        log::info(log_cat, "Shutting down network...");

        if (shutdown_immediate)
            close_immediate();
        else
            close_gracefully();

        if (loop_thread)
            loop_thread->join();

        endpoint_map.clear();

        log::info(log_cat, "Network shutdown complete");

#ifdef _WIN32
        if (loop_thread)
            WSACleanup();
#endif
    }

    void Network::setup_job_waker()
    {
        job_waker.reset(event_new(
                ev_loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* self) {
                    log::trace(log_cat, "processing job queue");
                    static_cast<Network*>(self)->process_job_queue();
                },
                this));
        assert(job_waker);
    }

    void Network::close_immediate()
    {
        log::info(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (loop_thread)
            event_base_loopbreak(ev_loop.get());
    }

    void Network::close_gracefully()
    {
        log::info(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::promise<void> pr;
        auto ft = pr.get_future();

        call([&]() mutable {
            for (const auto& ep : endpoint_map)
                ep->close_conns();

            pr.set_value();
        });

        ft.get();

        if (loop_thread)
            event_base_loopexit(ev_loop.get(), nullptr);
    }

    bool Network::in_event_loop() const
    {
        return std::this_thread::get_id() == loop_thread_id;
    }

    void Network::call_soon(std::function<void(void)> f, source_location src)
    {
        loop_trace_log(log_cat, src, "Event loop queueing `{}`", src.function_name());
        {
            std::lock_guard lock{job_queue_mutex};
            job_queue.emplace(std::move(f), std::move(src));
            log::trace(log_cat, "Event loop now has {} jobs queued", job_queue.size());
        }
        event_active(job_waker.get(), 0, 0);
    }

    void Network::process_job_queue()
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

}  // namespace oxen::quic
