#pragma once

extern "C"
{
#include <event2/event.h>
#include <event2/thread.h>
}

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <atomic>
#include <cstdint>
#include <forward_list>
#include <future>
#include <memory>
#include <thread>

namespace oxen::quic
{
    using Job = std::function<void()>;
    using loop_ptr = std::shared_ptr<::event_base>;
    using caller_id_t = uint16_t;

    static void setup_libevent_logging();

    class Loop;

    struct Ticker
    {
        friend class Loop;

      private:
        std::atomic<bool> _is_running{false};
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        void init_event(
                const loop_ptr& _loop,
                std::chrono::microseconds _t,
                std::function<void()> task,
                bool one_off = false,
                bool start_immediately = true,
                bool task_rescheduling = false);

        Ticker() = default;

      public:
        ~Ticker();

        bool is_running() const { return _is_running; }

        /** Starts the repeating event on the given interval on Ticker creation
            Returns:
                - true: event successfully started
                - false: event is already running, or failed to start the event
         */
        bool start();

        /** Stops the repeating event managed by Ticker
            Returns:
                - true: event successfully stopped
                - false: event is already stopped, or failed to stop the event
         */
        bool stop();
    };

    class Loop
    {
        friend class Network;

      protected:
        std::atomic<bool> running{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        template <std::invocable Callable>
        void add_oneshot_event(std::chrono::microseconds delay, Callable hook)
        {
            auto handler = make_shared<Ticker>();
            auto& h = *handler;

            h.init_event(
                    loop(),
                    delay,
                    [hndlr = std::move(handler), func = std::move(hook)]() mutable {
                        auto h = std::move(hndlr);
                        func();
                    },
                    true);
        }

      private:
        static constexpr caller_id_t loop_id{0};

        std::unordered_map<caller_id_t, std::list<std::weak_ptr<Ticker>>> tickers;

        void clear_old_tickers();

        std::shared_ptr<Ticker> make_handler(caller_id_t _id);

      public:
        Loop();

        Loop(const Loop&) = delete;
        Loop(Loop&&) = delete;
        Loop& operator=(Loop&&) = delete;
        Loop& operator=(Loop) = delete;

        virtual ~Loop();

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        bool in_event_loop() const { return std::this_thread::get_id() == loop_thread_id; }

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call([ptr] { delete ptr; }); };
        }

        // Returns a pointer deleter that defers invocation of a custom deleter to the event loop
        template <typename T, std::invocable<T*> Callable>
        auto wrapped_deleter(Callable f)
        {
            return [this, func = std::move(f)](T* ptr) mutable {
                return call_get([f = std::move(func), ptr]() { return f(ptr); });
            };
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

        // Similar to the above make_shared, but instead of forwarding arguments for the
        // construction of the object, it creates the shared_ptr from the already created object ptr
        // and wraps the object's deleter in a wrapped_deleter
        template <typename T, typename Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return std::shared_ptr<T>(obj, wrapped_deleter<T>(std::forward<Callable>(deleter)));
        }

        template <typename Callable>
        void call(Callable&& f)
        {
            if (in_event_loop())
            {
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f));
            }
        }

        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            if (in_event_loop())
            {
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

        /** This invocation of `call_every` will return an EventHandler object from which the application can start and stop
            the repeated event. It is NOT tied to the lifetime of the caller via a weak_ptr.

            Configurable parameters:
                - start_immediately: will call ::event_add() before returning the ticker.  This does *not* call the function
                    immediately.  If false then the ticker is not started and will not do anything until `start()` is called
                    on the ticker.
                - task_rescheduling:
                    - if `false` (default behavior), the ticker is on a fixed interval schedule, regardless of any scheduling
                        delays or how long the task itself takes to complete: the event loop will attempt to execute it
                        `interval`, measured from now.  Any scheduling delays or long time taken by the task in one call do
                        not affect the scheduling of future calls.
                    - if `true`, the event will be rescheduled each time it completes so that the next call will occur
                        `interval` after the previous one completes.  Thus any scheduling delays or time spent in the task
                        itself will cause the next call to be pushed later (to `interval` after task completion).
        */
        template <typename Callable>
        [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval,
                Callable&& f,
                bool start_immediately = true,
                bool task_rescheduling = false)
        {
            return _call_every(interval, std::forward<Callable>(f), Loop::loop_id, start_immediately, task_rescheduling);
        }

        template <std::invocable Callable>
        void call_later(std::chrono::microseconds delay, Callable hook)
        {
            if (in_event_loop())
            {
                add_oneshot_event(delay, std::move(hook));
            }
            else
            {
                call_soon([this, func = std::move(hook), target_time = get_time() + delay]() mutable {
                    auto now = get_time();

                    if (now >= target_time)
                        func();
                    else
                        add_oneshot_event(
                                std::chrono::duration_cast<std::chrono::microseconds>(target_time - now), std::move(func));
                });
            }
        }

        template <std::invocable Callable>
        void call_soon(Callable f)
        {
            {
                std::lock_guard lock{job_queue_mutex};
                job_queue.emplace(std::move(f));
            }

            event_active(job_waker.get(), 0, 0);
        }

      private:
        // private method invoked in Network destructor by final Network to close shared_ptr
        void stop_thread(bool immediate = true);

        void stop_tickers(caller_id_t _id);

        template <typename Callable>
        [[nodiscard]] std::shared_ptr<Ticker> _call_every(
                std::chrono::microseconds interval,
                Callable&& f,
                caller_id_t _id,
                bool start_immediately,
                bool task_rescheduling)
        {
            auto h = make_handler(_id);

            h->init_event(loop(), interval, std::forward<Callable>(f), false, start_immediately, task_rescheduling);

            return h;
        }

        void setup_job_waker();

        void process_job_queue();
    };
}  //  namespace oxen::quic
