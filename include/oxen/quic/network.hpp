#pragma once

#include "loop.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <unordered_set>
#include <utility>

namespace oxen::quic
{
    class Endpoint;
    struct Address;

    /** Network:
            This object is the entry point to libquic, providing functionalities like job scheduling and endpoint creation
        for application implementation. Networks can have one of two relationships to event loop that it manages:
            - Standard ownership: The event loop's lifetime is entirely managed within the Network object. It is not a
                publicly exposed attribute, and cannot be accessed to directly construct other networks "chained" off of the
                same event loop. If the application requires multiple networks that share one underlying event loop, invoking
                the `::create_linked_network()` method will return a new Network object sharing its own event loop. For the
                application code, this has the effect of only destroying the event loop when the last Network sharing it is
                destroyed.
            - Application ownership: The event loop's lifetime is entirely managed by the application code and managing
                context. A standalone Loop object is created and passed by value in each subsequent Network construction. It
                is the responsibility of the application code to ensure that the event loop is last to be destroyed. Objects
                like endpoints are held in shared_pointers with deleters scheduled on the event loop. The event loop must
                persist until all objects held externally (Network, Endpoint, Connection, etc) are destroyed.
     */

    class Network final
    {
      public:
        Network();
        explicit Network(std::shared_ptr<Loop> ev_loop);

        Network(const Network& n) : Network{n._loop} {}

        Network& operator=(Network) = delete;
        Network& operator=(Network&&) = delete;

        ~Network();

        [[nodiscard]] Network create_linked_network();

        bool in_event_loop() const { return _loop->in_event_loop(); }

        void call_soon(std::function<void(void)> f) { _loop->call_soon(std::move(f)); }

        template <typename... Opt>
        std::shared_ptr<Endpoint> endpoint(const Address& local_addr, Opt&&... opts)
        {
            auto [it, added] = endpoints.emplace(std::make_shared<Endpoint>(*this, local_addr, std::forward<Opt>(opts)...));

            return *it;
        }

        // Shuts down an endpoint, closing all connections and sockets in the process, and blocks
        // until the endpoint is fully destroyed.  This happens automatically upon Network
        // destruction, but can also be done in cases where the Network object is doing other
        // things.
        //
        // An application calling this is expected to call this as `close(std::move(endpoint))` to
        // give up ownership of its endpoint as part of the call.
        void close(std::shared_ptr<Endpoint>&& endpoint);

        // Same as close(std::move(endpoint)), except that this does not wait for shutdown to
        // complete.
        void close_soon(std::shared_ptr<Endpoint>&& endpoint);

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

        void reset_soon(std::shared_ptr<void> ptr)
        {
            call_soon([ptr = std::move(ptr)]() mutable { ptr.reset(); });
        }

        /** This invocation of `call_every` will return an EventHandler object from which the application can start and stop
            the repeated event. It is NOT tied to the lifetime of the caller via a weak_ptr.

            Configurable parameters:
                - start_immediately : will call ::event_add() before returning the ticker
                - wait :
                    - if FALSE (default behavior), the interval will not wait for the event to complete. will attempt to
                        execute every `interval`, regardless of how long the event itself takes.
                    - if TRUE, the interval will wait for the event to complete before beginning. It will wait the entire
                        `interval` after finishing execution of the event before attempting execution again.
        */
        template <typename Callable>
        [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval, Callable&& f, bool start_immediately = true, bool wait = false)
        {
            return _loop->_call_every(interval, std::forward<Callable>(f), net_id, start_immediately, wait);
        }

        template <typename Callable>
        void call_later(std::chrono::microseconds delay, Callable&& hook)
        {
            _loop->call_later(delay, std::forward<Callable>(hook));
        }

      private:
        std::shared_ptr<Loop> _loop;
        std::atomic<bool> shutdown_immediate{false};
        std::unordered_set<std::shared_ptr<Endpoint>> endpoints;

        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        void close_gracefully();

        const caller_id_t net_id;

        static caller_id_t next_net_id;
    };
}  // namespace oxen::quic
