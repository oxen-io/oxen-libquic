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
    Network::Network(std::shared_ptr<event_base> loop_ptr, std::thread::id thread_id) :
            _loop{std::make_shared<Loop>(std::move(loop_ptr), thread_id)}
    {
        log::trace(log_cat, "Created network context with pre-existing ev loop thread");
    }

    Network::Network() : _loop{std::make_shared<Loop>()} {}

    Network::~Network()
    {
        log::info(log_cat, "Shutting down network...");

        if (not shutdown_immediate)
            close_gracefully();

        _loop->shutdown(shutdown_immediate);

        endpoint_map.clear();

        log::info(log_cat, "Network shutdown complete");
    }

    void Network::close_gracefully()
    {
        log::info(log_cat, "{} called", __PRETTY_FUNCTION__);

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
