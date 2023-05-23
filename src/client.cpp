#include "client.hpp"

#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "connection.hpp"
#include "context.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Client::Client(
            std::shared_ptr<Handler> quic_manager,
            std::shared_ptr<ClientContext> ctx,
            ConnectionID& id,
            std::shared_ptr<uvw::UDPHandle> handle) :
            Endpoint{quic_manager}, context{ctx}
    {
        Path path{ctx->local, ctx->remote};

        log::trace(
                log_cat,
                "Client path: local={}:{}, remote={}:{}",
                path.local.ip.data(),
                path.local.port,
                path.remote.ip.data(),
                path.remote.port);

        auto conn = std::make_shared<Connection>(this, handler, id, std::move(path), handle);

        conn->on_stream_available = [](Connection& conn) {
            log::info(log_cat, "QUIC connection established, streams now available");
            try
            {
                conn.open_stream();
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "{}\n", e.what());
            }
        };

        log::trace(
                log_cat,
                "Mapping ngtcp2_conn in client registry to source_cid:{} (dcid: {})",
                *conn->source_cid.data,
                *conn->dest_cid.data);

        conns[conn->source_cid] = conn;
        conn->io_ready();

        log::info(log_cat, "Successfully created Client endpoint");
    }

    Client::~Client()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (expiry_timer)
            expiry_timer->close();
    }

    std::shared_ptr<Stream> Client::open_stream(stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        log::trace(log_cat, "Opening client stream...");
        auto ctx = reinterpret_cast<ClientContext*>(context.get());

        auto conn = get_conn(ctx->conn_id);
        auto stream = std::make_shared<Stream>(*conn, std::move(data_cb), std::move(close_cb));

        if (int rv = ngtcp2_conn_open_bidi_stream(*conn.get(), &stream->stream_id, stream.get()); rv != 0)
            throw std::runtime_error{"Stream creation failed: "s + ngtcp2_strerror(rv)};

        auto& str = conn->streams[stream->stream_id];

        str = std::move(stream);

        log::debug(log_cat, "Client stream opened");
        return str;
    }

    std::shared_ptr<uvw::UDPHandle> Client::get_handle(Address& addr)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }

    std::shared_ptr<uvw::UDPHandle> Client::get_handle(Path& p)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }
}  // namespace oxen::quic
