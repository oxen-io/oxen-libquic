#include "handler.hpp"
#include "context.hpp"
#include "network.hpp"
#include "crypto.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"

#include <uvw.hpp>

#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>


namespace oxen::quic
{
    Handler::Handler(std::shared_ptr<uvw::Loop> loop_ptr, Network& net) : net{net}
    {
        ev_loop = loop_ptr;
        universal_handle = ev_loop->resource<uvw::UDPHandle>();

        universal_handle->bind(default_local);
        net.mapped_client_addrs.emplace(Address{default_local}, universal_handle);

        log::info(log_cat, "{}", (ev_loop) ? 
            "Event loop successfully created" : 
            "Error: event loop creation failed");
    }


    Handler::~Handler()
    {
        log::debug(log_cat, "Shutting down tunnel manager...");

        for (const auto& itr : clients)
            itr->client->~Client();

        for (const auto& itr : servers)
            itr.second->server->~Server();
        
        if (ev_loop)
        {
            ev_loop->walk(uvw::Overloaded{[](uvw::UDPHandle &&h){ h.close(); }, [](auto&&){}});
            ev_loop->clear();
            ev_loop->stop();
            ev_loop->close();
            log::debug(log_cat, "Event loop shut down...");
        }

        clients.clear();
        servers.clear();
    }


    std::shared_ptr<uvw::Loop>
    Handler::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }


    void
    Handler::client_call_async(async_callback_t async_cb)
    {
        for (const auto& itr : clients)
        {
            itr->client->call_async_all(async_cb);
        }
    }


    void
    Handler::client_close()
    {
        for (const auto& c : clients)
        {
            
        }
    }

}   // namespace oxen::quic
