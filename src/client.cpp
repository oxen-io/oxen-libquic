#include "client.hpp"
#include "context.hpp"
#include "connection.hpp"
#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>


namespace oxen::quic
{
    Client::Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx, ConnectionID& id, std::shared_ptr<uvw::UDPHandle> handle) : 
        Endpoint{quic_manager},
        context{ctx}
    {
        default_stream_bufsize = 0;

        Path path{ctx->local, ctx->remote};

        fprintf(stderr, "Client path: local=%s:%u, remote=%s:%u\n", path.local.ip.data(), path.local.port, path.remote.ip.data(), path.remote.port);

        auto conn = std::make_shared<Connection>(this, handler, id, std::move(path), handle);

        conn->on_stream_available = [](Connection& conn) 
        {
            fprintf(stderr, "QUIC connection established, streams now available\n");
            try 
            {
                conn.open_stream();
            }
            catch (const std::exception& e)
            {
                fprintf(stderr, "%s\n", e.what());
            }
        };

        conns[conn->source_cid] = conn;
        conn->io_ready();

        fprintf(stderr, "Successfully created Client endpoint\n");
    }


    Client::~Client()
    {
        //
    }


    std::shared_ptr<Stream>
    Client::open_stream(size_t bufsize, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        fprintf(stderr, "Opening client stream...\n");
        auto ctx = reinterpret_cast<ClientContext*>(context.get());

        auto conn = get_conn(ctx->conn_id);
        auto str = std::make_shared<Stream>(*conn, bufsize, std::move(data_cb), std::move(close_cb));

        if (int rv = ngtcp2_conn_open_bidi_stream(conn.get()->operator ngtcp2_conn*(), &str->stream_id, str.get()); rv != 0)
            throw std::runtime_error{"Stream creation failed: "s + ngtcp2_strerror(rv)};

        conn->streams.emplace(str->stream_id, str);

        return str;
    }


    std::shared_ptr<uvw::UDPHandle>
    Client::get_handle(Address& addr)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }

    std::shared_ptr<uvw::UDPHandle>
    Client::get_handle(Path& p)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }
}   // namespace oxen::quic
