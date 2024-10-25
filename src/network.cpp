#include "network.hpp"

#include <exception>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

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

    Network Network::create_linked_network()
    {
        return Network{_loop};
    }

    void Network::close_gracefully()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::promise<void> pr;
        auto ft = pr.get_future();

        _loop->call([&]() mutable {
            for (const auto& ep : endpoint_map)
                ep->_close_conns(std::nullopt);

            pr.set_value();
        });

        ft.get();
    }
}  // namespace oxen::quic
