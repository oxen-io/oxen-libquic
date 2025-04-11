#include "network.hpp"

#include "internal.hpp"

#include <memory>

namespace oxen::quic
{
    Network::Network(std::shared_ptr<Loop> ev_loop) : _loop{std::move(ev_loop)}
    {
        if (!_loop)
            _loop = std::make_shared<Loop>();

        log::trace(log_cat, "Network wrapper created");
    }

    Network::~Network()
    {
        if (not shutdown_immediate)
            close();

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

    void Network::close()
    {
        log::debug(log_cat, "Shutting down network...");
        // Endpoint's own destructor will _close_conns on itself, but just in case the app is
        // holding a shared pointer, we still want to close everything because, when using Network
        // rather than holding Endpoints yourself, it is supposed to be in charge.
        _loop->call_get([this] {
            for (const auto& ep : endpoints)
                ep->_close_conns(std::nullopt);
        });

        endpoints.clear();

        set_shutdown_immediate();

        log::info(log_cat, "Network shutdown complete");
    }

    void Network::close_soon()
    {
        log::debug(log_cat, "Shutting down network...");
        _loop->call([this] {
            for (const auto& ep : endpoints)
                ep->_close_conns(std::nullopt);

            endpoints.clear();

            set_shutdown_immediate();

            log::info(log_cat, "Network shutdown complete");
        });
    }

}  // namespace oxen::quic
