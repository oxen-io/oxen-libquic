#include "network.hpp"
#include "context.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>

#include <uvw.hpp>

#include <stdexcept>
#include <string_view>
#include <memory>


namespace oxen::quic
{
    Network::Network(std::shared_ptr<uvw::Loop> loop_ptr)
    {
        log::trace(log_cat, "Beginning context creation");
        ev_loop = (loop_ptr) ? loop_ptr : uvw::Loop::create();
        quic_manager = std::make_shared<Handler>(ev_loop, *this);
    }


    Network::~Network()
    {
        log::info(log_cat, "Shutting down context...");
    }


    void
    Network::run()
    {
        if (!ev_loop->alive())
            ev_loop->run();
        else
            log::info(log_cat, "Event loop already alive");
    }


    void
    Network::configure_client_handle(std::shared_ptr<uvw::UDPHandle> handle)
    {
        // client receive data
        handle->on<uvw::UDPDataEvent>([&](const uvw::UDPDataEvent &event, uvw::UDPHandle &handle) 
        {
            bstring_view data{reinterpret_cast<const std::byte*>(event.data.get()), event.length};

            Packet pkt{.path = Path{handle.sock(), event.sender}, .data = data};

            log::trace(log_cat, "Client received packet from sender {}:{}", pkt.path.remote.ip.data(), pkt.path.remote.port);
            log::trace(log_cat, "Searching client mapping for local address {}:{}", pkt.path.local.ip.data(), pkt.path.local.port);
            
            for (auto ctx : quic_manager->clients)
            {
                if (ctx->local == handle.sock())
                    ctx->client->handle_packet(pkt);
                else
                    log::warning(log_cat, "Client handle forwarding unsuccessful");
            }
        });
    }


    void
    Network::configure_server_handle(std::shared_ptr<uvw::UDPHandle> handle)
    {
        // server receive data
        handle->on<uvw::UDPDataEvent>([&](const uvw::UDPDataEvent &event, uvw::UDPHandle &handle) 
        {
            bstring_view data{reinterpret_cast<const std::byte*>(event.data.get()), event.length};
            
            Packet pkt{.path = Path{handle.sock(), event.sender}, .data = data};

            log::trace(log_cat, "Server received packet from sender {}:{}", pkt.path.remote.ip.data(), pkt.path.remote.port);
            log::trace(log_cat, "Searching server mapping for local address {}:{}", pkt.path.local.ip.data(), pkt.path.local.port);

            auto itr = quic_manager->servers.find(pkt.path.local);

            if (itr != quic_manager->servers.end())
                itr->second->server->handle_packet(pkt);
            else
                log::warning(log_cat, "Server handle forwarding unsuccessful");
        });
    }


    std::shared_ptr<uvw::UDPHandle>
    Network::handle_client_mapping(Address& local)
    {
        auto q = mapped_client_addrs.find(local);

        if (q == mapped_client_addrs.end())
        {
            log::trace(log_cat, "Creating dedicated client udp_handle...");
            auto handle = quic_manager->loop()->resource<uvw::UDPHandle>();
            configure_client_handle(handle);
            // binding is done here rather than after returning, so an already bound
            // UDPhandle isn't bound to the same address twice
            handle->bind(local);
            handle->recv();
            mapped_client_addrs[local] = handle;
            return handle;
        }

        return q->second;
    }


    std::shared_ptr<uvw::UDPHandle>
    Network::handle_server_mapping(Address& local)
    {
        auto q = mapped_server_addrs.find(local);

        if (q == mapped_server_addrs.end())
        {
            log::trace(log_cat, "Creating dedicated server udp_handle...");
            auto handle = quic_manager->loop()->resource<uvw::UDPHandle>();
            configure_server_handle(handle);
            handle->bind(local);
            handle->recv();
            mapped_server_addrs[local] = handle;
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
