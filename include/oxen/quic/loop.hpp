#pragma once

#include "utils.hpp"

#include <future>
#include <list>
#include <memory>
#include <queue>
#include <thread>

struct event_base;

namespace oxen::quic
{
    using Job = std::function<void()>;

    class Loop;

    struct Ticker
    {
        friend class Loop;

      private:
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        void init_event(
                ::event_base* loop, std::chrono::microseconds _t, std::function<void()> task, bool start_immediately = true);

        Ticker() = default;

      public:
        ~Ticker();

        /** Starts the repeating event on the given interval on Ticker creation.  Does nothing if
         *   already active.
            Returns:
                - true: event successfully started
                - false: event is already running, or failed to start the event
         */
        bool start();

        /** Stops the repeating event managed by Ticker.  Does nothing if not currently active.
            Returns:
                - true: event successfully stopped
                - false: event is already stopped, or failed to stop the event
         */
        bool stop();
    };

    /// An event loop task that can be fired multiple times, but is triggered manually when needed
    /// to schedule a callback call on the event loop.  Unlike using `call`/`call_soon`, calls to
    /// trigger/wake the event are idempotent: i.e. the event will be called only once regardless of
    /// how many wakeups there were prior to the call.  Once called, it will not be schedule again
    /// until triggered at least once more.
    ///
    /// Construct via Loop::make_wakeable().
    class Wakeable
    {
        friend class Loop;

        event_ptr ev;
        std::function<void()> f;

        Wakeable() = default;

      public:
        /// Call to schedule f() to be called, if not already scheduled.
        void wake();
    };

    class Loop
    {
      protected:
        std::unique_ptr<::event_base, void (*)(struct ::event_base*)> ev_loop;
        std::thread loop_thread;
        std::thread::id loop_thread_id;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        void add_oneshot_event(std::chrono::microseconds delay, std::function<void()> hook);

      private:
        std::list<std::weak_ptr<Ticker>> tickers;

        std::shared_ptr<Ticker> make_ticker();

        // call_later events aren't guaranteed to get properly disposed off if the event loop stops
        // before it fires, so we stash it in here temporarily and remove it when fired.  During the
        // Loop destructor, then, if there's anything left that's one that needs to be cleaned up.
        struct OneShotDelayed;
        std::list<OneShotDelayed*> delayed_events;

      public:
        Loop();

        Loop(const Loop&) = delete;
        Loop(Loop&&) = delete;
        Loop& operator=(Loop&&) = delete;
        Loop& operator=(Loop) = delete;

        virtual ~Loop();

        ::event_base* get_event_base() const { return ev_loop.get(); }

        bool inside() const { return std::this_thread::get_id() == loop_thread_id; }

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call_get([ptr] { delete ptr; }); };
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
        // thread safety, and waits for destruction of the overlying object to complete before
        // returning.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::shared_ptr<T>{ptr, loop_deleter<T>()};
        }

        // Similar to the above make_shared, but instead of forwarding arguments for the
        // construction of the object, it creates the shared_ptr from the already created object ptr
        // and wraps the object's deleter in a wrapped_deleter
        template <typename T, std::invocable<T*> Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return std::shared_ptr<T>(obj, wrapped_deleter<T>(std::forward<Callable>(deleter)));
        }

        /// Calls `f()` on the event loop.  If the caller is already in the event loop thread then
        /// f() is called immediately; otherwise it is scheduled on the event loop thread at the
        /// next available opportunity.
        template <std::invocable<> Callable>
        void call(Callable&& f)
        {
            if (inside())
            {
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f));
            }
        }

        // Calls `f()` on the event loop and returns its value.  If this is called from within the
        // event loop thread then this simply calls and returns the result of `f()`.  If *not* in
        // the event loop then a call to `f()` is scheduled on the event loop for the next available
        // opportunity and then the current thread blocks until that call is invoked, then returns
        // it back to the caller.
        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            if (inside())
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

        /// Sets up a task `f()` to be called on the event loop periodically.
        ///
        /// `interval` controls the interval on which the task will be called.
        ///
        /// `start_immediately` controls whether the task is scheduled on the event loop right away
        /// (true, the default), or not (false).  If not started immediately then the task will not
        /// fire until `start()` is called on it.  (Note that this parameter does not mean "call
        /// immediately" -- it simply controls whether the initial timer for the first call is
        /// started or not).
        ///
        /// The ticker will remain active as long the loop remains active and the returned Ticker
        /// object is kept alive.
        template <std::invocable<> Callable>
        [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval, Callable&& f, bool start_immediately = true)
        {
            auto h = make_ticker();
            h->init_event(get_event_base(), interval, std::forward<Callable>(f), start_immediately);
            return h;
        }

        /// Schedules a call of `f()` on the event loop after a delay.
        template <std::invocable<> Callable>
        void call_later(std::chrono::microseconds delay, Callable hook)
        {
            if (inside())
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

        /// Creates a Wakeable event tied to this event loop that can be manually triggered when
        /// desired to schedule an invocation of the callback.  Unlike call_soon, this is idempotent
        /// (i.e. multiple wakeups before it actually runs does not schedule multiple calls).  Note
        /// that this call only constructs the event, but does not initially schedule it.
        std::shared_ptr<Wakeable> make_wakeable(std::function<void()> hook);

        static void activate(::event& evt);

        /// Schedules a call of `f()` at the next available opportunity on the event loop.  Unlike
        /// `call()`, `call_soon()` never calls f() immediately even if already inside the event
        /// loop.
        template <std::invocable<> Callable>
        void call_soon(Callable f)
        {
            {
                std::lock_guard lock{job_queue_mutex};
                job_queue.emplace(std::move(f));
            }

            activate(*job_waker);
        }

        /// Takes any type of shared_ptr and schedules a reset of that shared pointer on the event
        /// loop.  Asyncronous.
        template <typename T>
        void reset_soon(std::shared_ptr<T>&& ptr)
        {
            call_soon([ptr = std::move(ptr)]() mutable { ptr.reset(); });
        }

      private:
        void setup_job_waker();

        void process_job_queue();
    };
}  //  namespace oxen::quic
