#include "network.hpp"

#include "endpoint.hpp"
#include "internal.hpp"

#include <cassert>
#include <memory>
#include <optional>

namespace oxen::quic
{
    caller_id_t Network::next_net_id = 0;

    Network::Network(std::shared_ptr<Loop> ev_loop) : _loop{std::move(ev_loop)}, net_id{++next_net_id}
    {
        log::trace(log_cat, "Creating network context with pre-existing event loop!");
    }

    Network::Network() : _loop{std::make_shared<Loop>()}, net_id{++next_net_id} {}

    Network::~Network()
    {
        log::debug(log_cat, "Shutting down network...");

        if (not shutdown_immediate)
            close_gracefully();

        // If the loop is internally managed by the Network ("standard ownership"), then this ensures that the last Network
        // to turn the lights off has time to allow for any final objects to be destructed off of the event loop
        if (_loop.use_count() == 1)
            _loop->stop_thread(shutdown_immediate);

        _loop->stop_tickers(net_id);

        log::info(log_cat, "Network shutdown complete");
    }

    void Network::close(std::shared_ptr<Endpoint>&& endpoint)
    {
        assert(endpoint);
        if (endpoint.use_count() > 2)
            log::warning(
                    log_cat,
                    "Network::close() called with an endpoint with extra owners; closing will not be complete until "
                    "remaining shared_ptr instances are destroyed");

        _loop->call_get([this, &endpoint] {
            endpoint->_close_conns(std::nullopt);
            if (!endpoints.erase(endpoint))
                log::warning(log_cat, "Network::close() called with an endpoint that does not belong to it");
        });
        endpoint.reset();
    }

    void Network::close_soon(std::shared_ptr<Endpoint>&& endpoint)
    {
        assert(endpoint);
        if (endpoint.use_count() > 2)
            log::warning(
                    log_cat,
                    "Network::close_soon() called with an endpoint with extra owners; closing will not be complete until "
                    "remaining shared_ptr instances are destroyed");

        _loop->call([this, endpoint = std::move(endpoint)] {
            endpoint->_close_conns(std::nullopt);
            if (!endpoints.erase(endpoint))
                log::warning(log_cat, "Network::close_soon() called with an endpoint that does not belong to it");
        });
    }

    Network Network::create_linked_network()
    {
        return Network{_loop};
    }

    void Network::close_gracefully()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        _loop->call_get([this] {
            for (const auto& ep : endpoints)
                ep->_close_conns(std::nullopt);
        });
    }
}  // namespace oxen::quic
