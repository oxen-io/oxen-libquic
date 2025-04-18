#pragma once

#include "endpoint.hpp"
#include "loop.hpp"

#include <atomic>
#include <memory>

namespace oxen::quic
{
    /**
     * The Network object is a convenience holder for an event loop and one or more endpoints, which
     * performs graceful shutdown (by default) during destruction.  Its use is entirely optional:
     * using Network is equivalent to holding your own shared_ptr<Loop> and shared_ptr<Endpoint>s
     * directly, and calling endpoint->close_conns() before destruction to initiate a graceful
     * shutdown.
     */
    class Network final
    {
      public:
        // Network constructor; it can use an existing event loop, but if not given one, it will
        // create its own (that can be retrieved via `loop()`).
        explicit Network(std::shared_ptr<Loop> ev_loop = nullptr);

        Network(const Network& n) = delete;
        Network(Network&& n) = delete;
        Network& operator=(const Network&) = delete;
        Network& operator=(Network&&) = delete;

        ~Network();

        // Returns a shared_ptr to the network's Loop object, which can be shared by other things
        // needing an event loop if desired.
        const std::shared_ptr<Loop>& loop() const { return _loop; }

        // Constructs a new endpoint, and stores it in this Network object.  The endpoint will be
        // kept alive by the Network object.  If the caller stores the returned shared_ptr then the
        // caller must ensure that it does not allow the endpoint to outlive the Network.
        template <typename... Opt>
        const std::shared_ptr<Endpoint>& endpoint(const Address& local_addr, Opt&&... opts)
        {
            return *endpoints.insert(Endpoint::endpoint(*_loop, local_addr, std::forward<Opt>(opts)...)).first;
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

        // Initiates shutdown of the entire Network instance by closing all of the connections on
        // this object, synchronously.  This is normally called during destruction, but can also be
        // called manually to control the sequence of shutdown (for instance, if connections or
        // streams have callbacks that will be fired during destruction that need a Network instance
        // to remain alive externally).
        //
        // The caller should consider the Network dead and *must not* perform any network operations
        // (such as creating a new connection) after calling this.
        //
        // Calling this implicitly calls `set_shutdown_immediate()` so that, after this call,
        // destruction will happen assuming all connections/streams have been properly terminated.
        void close();

        // Initiates shutdown (as close() does), but does not wait for closing to complete.
        void close_soon();

        // Sets "immediate" shutdown mode: if this is enabled then, during destructions, endpoints
        // are closed immediately without attempting to send a close message to connected peers.
        void set_shutdown_immediate(bool b = true) { shutdown_immediate = b; }

      private:
        std::shared_ptr<Loop> _loop;
        std::atomic<bool> shutdown_immediate{false};
        std::unordered_set<std::shared_ptr<Endpoint>> endpoints;
    };
}  // namespace oxen::quic
