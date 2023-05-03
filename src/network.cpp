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
        quic_manager = std::make_shared<Handler>(ev_loop, *this);
    }


    Network::~Network()
    {
        fprintf(stderr, "Shutting down context...\n");
    }


    std::shared_ptr<uvw::UDPHandle>
    Network::handle_mapping(Address& addr)
    {
        auto q = mapped_client_addrs.find(addr);

        if (q == mapped_client_addrs.end())
        {
            auto handle = quic_manager->loop()->resource<uvw::UDPHandle>();
            mapped_client_addrs.emplace(Address{addr}, handle);
            return handle;
        }

        return q->second;
    }


    Handler*
    Network::get_quic()
    {
        return (quic_manager) ? quic_manager.get() : nullptr;
    }
}   // namespace oxen::quic
