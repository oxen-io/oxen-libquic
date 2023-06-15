#include "client.hpp"

extern "C"
{
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
}

#include <cstdio>
#include <cstring>
#include <future>
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
            std::shared_ptr<uv_udp_t> handle) :
            Endpoint{quic_manager}, context{ctx}
    {
        Path path{ctx->local, ctx->remote};

        log::trace(log_cat, "Client path: {}", path);

        auto conn = std::make_unique<Connection>(*this, handler, id, std::move(path), handle, context->config);

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

        std::promise<std::shared_ptr<Stream>> p;
        auto f = p.get_future();
        handler->call([&data_cb, &close_cb, &p, this]() {
            try
            {
                auto conn = get_conn(context->conn_id);

                p.set_value(conn->get_new_stream(
                        context->stream_data_cb ? context->stream_data_cb : std::move(data_cb), std::move(close_cb)));
            }
            catch (...)
            {
                p.set_exception(std::current_exception());
            }
        });

        return f.get();
    }

    std::shared_ptr<uv_udp_t> Client::get_handle(Address& addr)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }

    std::shared_ptr<uv_udp_t> Client::get_handle(Path& p)
    {
        return reinterpret_cast<ClientContext*>(context.get())->udp_handle;
    }
}  // namespace oxen::quic
