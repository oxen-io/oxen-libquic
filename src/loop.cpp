#include "loop.hpp"

#include "internal.hpp"

#include <event2/event.h>
#include <event2/thread.h>

#include <fmt/ranges.h>

namespace oxen::quic
{
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
                default:
                    log::debug(ev_cat, "{}", msg);
                    break;
            }
        });
    }

    static timeval loop_time_to_timeval(std::chrono::microseconds t)
    {
#ifdef _WIN32
        using suseconds_t = long;
#endif
        return timeval{.tv_sec = static_cast<time_t>(t / 1s), .tv_usec = static_cast<suseconds_t>((t % 1s) / 1us)};
    }

    bool Ticker::start()
    {
        if (event_add(ev.get(), &interval) != 0)
        {
            log::warning(log_cat, "EventHandler failed to start repeating event!");
            return false;
        }

        return true;
    }

    bool Ticker::stop()
    {
        if (event_del(ev.get()) != 0)
        {
            log::warning(log_cat, "EventHandler failed to pause repeating event!");
            return false;
        }

        return true;
    }

    void Ticker::init_event(
            ::event_base* loop, std::chrono::microseconds t, std::function<void()> task, bool start_immediately)
    {
        f = std::move(task);

        interval = loop_time_to_timeval(t);

        ev.reset(event_new(
                loop,
                -1,
                EV_PERSIST,
                [](evutil_socket_t, short, void* s) {
                    try
                    {
                        auto* self = reinterpret_cast<Ticker*>(s);
                        if (not self->f)
                        {
                            log::warning(log_cat, "Ticker does not have a callback to execute!");
                            return;
                        }
                        // execute callback
                        self->f();
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(log_cat, "Ticker caught exception: {}", e.what());
                    }
                },
                this));

        if (start_immediately and not start())
            log::warning(log_cat, "Failed to immediately start one-off event!");
    }

    Ticker::~Ticker()
    {
        ev.reset();
        f = nullptr;
    }

    static std::vector<std::string_view> get_ev_methods()
    {
        std::vector<std::string_view> ev_methods_avail;
        for (const char** methods = event_get_supported_methods(); methods && *methods; methods++)
            ev_methods_avail.emplace_back(*methods);
        return ev_methods_avail;
    }

    Loop::Loop() : ev_loop{nullptr, ::event_base_free}
    {
        log::trace(log_cat, "Beginning loop context creation with new ev loop thread");

#ifdef _WIN32
        {
            WSADATA ignored;
            if (int err = WSAStartup(MAKEWORD(2, 2), &ignored); err != 0)
            {
                log::critical(log_cat, "WSAStartup failed to initialize the windows socket layer ({:x})", err);
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

        static std::vector<std::string_view> ev_methods_avail = get_ev_methods();
        log::debug(
                log_cat,
                "Starting libevent {}; available backends: {}",
                event_get_version(),
                "{}"_format(fmt::join(ev_methods_avail, ", ")));

        std::unique_ptr<event_config, decltype(&event_config_free)> ev_conf{event_config_new(), event_config_free};
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_PRECISE_TIMER);
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_NO_CACHE_TIME);
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

        ev_loop = {event_base_new_with_config(ev_conf.get()), event_base_free};

        log::debug(log_cat, "Started libevent loop with backend {}", event_base_get_method(ev_loop.get()));

        setup_job_waker();

        std::promise<void> p;

        loop_thread = std::thread{[this, &p] {
            log::debug(log_cat, "Starting event loop run");
            p.set_value();
            event_base_loop(ev_loop.get(), EVLOOP_NO_EXIT_ON_EMPTY);
            log::debug(log_cat, "Event loop run returned, thread finished");
        }};

        loop_thread_id = loop_thread.get_id();
        p.get_future().get();

        log::info(log_cat, "libevent loop is started");
    }

    struct Loop::OneShotDelayed
    {
        Loop& loop;
        std::function<void()> f;

        OneShotDelayed(Loop& loop, std::function<void()> f) : loop{loop}, f{std::move(f)} {}
    };

    Loop::~Loop()
    {
        log::debug(log_cat, "Shutting down loop...");

        for (auto& t : tickers)
        {
            if (auto tick = t.lock())
            {
                tick->f = nullptr;
                tick->stop();
            }
        }

        for (auto* osd : delayed_events)
            delete osd;
        delayed_events.clear();

        event_base_loopbreak(ev_loop.get());
        loop_thread.join();

        log::info(log_cat, "Loop shutdown complete");

#ifdef _WIN32
        WSACleanup();
#endif
    }

    std::shared_ptr<Ticker> Loop::make_ticker()
    {
        std::erase_if(tickers, [](auto& wp) { return wp.expired(); });
        auto t = make_shared<Ticker>();
        tickers.emplace_back(t);
        return t;
    }

    std::shared_ptr<Wakeable> Loop::make_wakeable(std::function<void()> callback)
    {
        auto w = make_shared<Wakeable>();
        w->f = std::move(callback);
        w->ev.reset(event_new(
                ev_loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* w) {
                    auto* wakeable = static_cast<Wakeable*>(w);
                    if (wakeable->f)
                        wakeable->f();
                },
                w.get()));
        return w;
    }

    void Wakeable::wake()
    {
        event_active(ev.get(), 0, 0);
    }

    void Loop::setup_job_waker()
    {
        // Almost identical to the generic make_wakeable, except that we avoid the std::function and
        // its implicit virtual function call.
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

    void Loop::add_oneshot_event(std::chrono::microseconds delay, std::function<void()> hook)
    {
        auto* handler = new OneShotDelayed{*this, std::move(hook)};
        delayed_events.push_back(handler);
        auto& h = *handler;
        const auto delay_tv = loop_time_to_timeval(delay);
        event_base_once(
                get_event_base(),
                -1,
                EV_TIMEOUT,
                [](evutil_socket_t, short, void* e) mutable {
                    auto* h = static_cast<OneShotDelayed*>(e);
                    if (h->f)
                        h->f();
                    auto& de = h->loop.delayed_events;
                    if (auto it = std::find(de.begin(), de.end(), h); it != de.end())
                        de.erase(it);
                    delete h;
                },
                &h,
                &delay_tv);
    }

    void Loop::process_job_queue()
    {
        log::trace(log_cat, "Event loop processing job queue");
        assert(inside());

        decltype(job_queue) swapped_queue;

        {
            std::lock_guard<std::mutex> lock{job_queue_mutex};
            job_queue.swap(swapped_queue);
        }

        while (not swapped_queue.empty())
        {
            auto job = swapped_queue.front();
            swapped_queue.pop();
            job();
        }
    }

    // Wrapper around event_active so that we can keep libevent out of the public headers.
    void Loop::activate(::event& evt)
    {
        event_active(&evt, 0, 0);
    }

}  //  namespace oxen::quic
