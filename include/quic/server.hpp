#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <uvw.hpp>

#include "context.hpp"
#include "endpoint.hpp"
#include "handler.hpp"
#include "stream.hpp"

namespace oxen::quic
{
    class Server : public Endpoint
    {
      public:
        std::shared_ptr<ServerContext> context;

        Server(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ServerContext> ctx) :
                Endpoint{quic_manager}, context{ctx}
        {
            log::trace(log_cat, "Successfully created Server endpoint");
        }

        ~Server();

        std::shared_ptr<Stream> open_stream(
                Connection* conn, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<Stream> open_stream(
                ConnectionID conn_id, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<Stream> open_stream(
                const Address& remote_addr,
                stream_data_callback_t data_cb = nullptr,
                stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<uv_udp_t> get_handle(Address& addr) override;

        std::shared_ptr<uv_udp_t> get_handle(Path& p) override;

      protected:
        Connection* accept_initial_connection(Packet& pkt, ConnectionID& dcid) override;
    };

}  // namespace oxen::quic
