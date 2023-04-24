#include "client.hpp"
#include "connection.hpp"

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>


namespace oxen::quic
{
    Client::Client(Handler& handler, const uint16_t remote_port, Address& remote, Address& local) 
        : Endpoint{handler}
    {
        default_stream_bufsize = 0;
    
        if (remote_port == 0)
            throw std::logic_error{"Cannot tunnel to port 0"};

        Path path{local, remote};

        auto conn = std::make_shared<Connection>(*this, handler, ConnectionID::random(), std::move(path), remote_port);
        
        conn->io_ready();
        conns.emplace(conn->source_cid, std::move(conn));
    }


    Client::Client(Handler& handler) 
        : Endpoint{handler}
    {
        default_stream_bufsize = 0;
    }


    ConnectionID
    Client::make_conn(const uint16_t remote_port, Address& remote, Address& local)
    {
        auto ID = ConnectionID::random();

        Path path{local, remote};

        auto conn = std::make_shared<Connection>(*this, handler, ID, std::move(path), remote_port);
        
        conn->io_ready();
        conns.emplace(conn->source_cid, std::move(conn));

        return ID;
    }

}   // namespace oxen::quic
