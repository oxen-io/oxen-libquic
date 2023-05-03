#include "network.hpp"
#include "context.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <uvw.hpp>

#include <stdexcept>
#include <memory>


namespace oxen::quic
{
    Network::Network(std::shared_ptr<uvw::Loop> loop_ptr)
    {
        fprintf(stderr, "Beginning context creation\n");
        ev_loop = (loop_ptr) ? loop_ptr : uvw::Loop::create();
        quic_manager = std::make_shared<Handler>(ev_loop);
    }


    Network::~Network()
    {
        fprintf(stderr, "Shutting down context...\n");
    }


    Handler*
    Network::get_quic()
    {
        return (quic_manager) ? quic_manager.get() : nullptr;
    }
}   // namespace oxen::quic
