#pragma once

extern "C"
{
#include <event2/event.h>
#include <event2/thread.h>
}

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    using Job = std::function<void()>;

    static void setup_libevent_logging();

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
        Loop();
        Loop(std::shared_ptr<::event_base> loop_ptr, std::thread::id thread_id);

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
        template <typename T, typename Callable>
        auto wrapped_deleter(Callable&& f)
        {
            return [this, f = std::move(f)](T* ptr) { return call_get([f = std::move(f), ptr]() { return f(ptr); }); };
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
            return std::shared_ptr<T>(obj, wrapped_deleter<T>(std::move(deleter)));
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

        void call_soon(std::function<void(void)> f);

        void shutdown(bool immediate = false);

      private:
        void setup_job_waker();

        void process_job_queue();
    };
}  //  namespace oxen::quic
