#pragma once

#include <event2/event.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>

#include "loop.hpp"

namespace oxen::quic
{
    class Endpoint;

    class Network
    {
      public:
        Network(std::shared_ptr<::event_base> loop_ptr, std::thread::id loop_thread_id);
        Network(std::shared_ptr<Loop> ev_loop);
        Network();
        ~Network();

        const std::shared_ptr<::event_base>& ev_loop() const { return _loop->loop(); }

        const std::shared_ptr<Loop>& loop() const { return _loop; }

        bool in_event_loop() const { return _loop->in_event_loop(); }

        void call_soon(std::function<void(void)> f) { _loop->call_soon(std::move(f)); }

        template <typename... Opt>
        std::shared_ptr<Endpoint> endpoint(const Address& local_addr, Opt&&... opts)
        {
            auto [it, added] =
                    endpoint_map.emplace(std::make_shared<Endpoint>(*this, local_addr, std::forward<Opt>(opts)...));

            return *it;
        }

        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return _loop->make_shared<T>(std::forward<Args>(args)...);
        }

        void set_shutdown_immediate(bool b = true) { shutdown_immediate = b; }

        template <typename Callable>
        void call(Callable&& f)
        {
            _loop->call(std::forward<Callable>(f));
        }

        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            return _loop->call_get(std::forward<Callable>(f));
        }

      private:
        std::shared_ptr<Loop> _loop;
        std::atomic<bool> shutdown_immediate{false};
        std::unordered_set<std::shared_ptr<Endpoint>> endpoint_map;

        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        void close_gracefully();
    };
}  // namespace oxen::quic
