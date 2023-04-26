#include "client.hpp"
#include "context.hpp"
#include "connection.hpp"

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>


namespace oxen::quic
{
    Client::Client(std::shared_ptr<Handler> quic_manager, const uint16_t remote_port, Address& remote, Address& local) 
        : Endpoint{quic_manager}
    {
        default_stream_bufsize = 0;
    
        if (remote_port == 0)
            throw std::logic_error{"Cannot tunnel to port 0"};

        Path path{local, remote};

        auto conn = std::make_shared<Connection>(*this, handler, ConnectionID::random(), std::move(path), remote_port);
        
        conn->io_ready();
        conns.emplace(conn->source_cid, std::move(conn));
    }


    Client::Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx) 
        : Endpoint{quic_manager}
    {
        default_stream_bufsize = 0;
        context = ctx;
    }


    std::pair<ConnectionID&, std::shared_ptr<Connection>>
    Client::make_conn(Address& remote, Address& local)
    {
        auto ID = ConnectionID::random();

        Path path{local, remote};

        auto conn = std::make_shared<Connection>(*this, handler, ID, std::move(path), remote.port);
        
        conn->io_ready();
        conns.emplace(conn->source_cid, std::move(conn));

        return {ID, conn};
    }

}   // namespace oxen::quic
