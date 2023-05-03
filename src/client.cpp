#include "client.hpp"
#include "context.hpp"
#include "connection.hpp"
#include "utils.hpp"

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>


namespace oxen::quic
{
    Client::Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx, ConnectionID& id) 
        : Endpoint{quic_manager}
    {
        default_stream_bufsize = 0;
        context = ctx;

        Path path{ctx->local, ctx->remote};

        auto conn = std::make_shared<Connection>(*this, handler, id, std::move(path));

        conn->io_ready();
        conns.emplace(conn->source_cid, conn);
    }


    Client::~Client()
    {
        
    }


    std::pair<ConnectionID&, std::shared_ptr<Connection>>
    Client::make_conn(Address& remote, Address& local)
    {
        auto ID = ConnectionID::random();

        Path path{local, remote};

        auto conn = std::make_shared<Connection>(*this, handler, ID, std::move(path), remote.port);
        
        conn->io_ready();
        conns.emplace(conn->source_cid, conn);

        return {ID, conn};
    }

}   // namespace oxen::quic
