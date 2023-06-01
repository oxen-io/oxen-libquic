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

        auto conn = std::make_unique<Connection>(*this, handler, id, std::move(path), handle);

        log::trace(
                log_cat,
                "Mapping ngtcp2_conn in client registry to source_cid:{} (dcid: {})",
                *conn->source_cid.data,
                *conn->dest_cid.data);

        conn->io_ready();
        conns.emplace(conn->source_cid, std::move(conn));

        log::info(log_cat, "Successfully created Client endpoint");
    }

    Client::~Client()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (expiry_timer)
            expiry_timer->close();
    }

    // only push into pending if rv is blocked
    std::shared_ptr<Stream> Client::open_stream(stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        log::trace(log_cat, "Opening client stream...");
        auto ctx = reinterpret_cast<ClientContext*>(context.get());

        auto conn = get_conn(ctx->conn_id);
        
        return conn->get_new_stream(std::move(data_cb), std::move(close_cb));
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
