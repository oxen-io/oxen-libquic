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
#include <string_view>
#include <uvw.hpp>

#include "endpoint.hpp"
#include "handler.hpp"
#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class ClientContext;

    class Client : public Endpoint
    {
      public:
        std::shared_ptr<ClientContext> context;

        Client(std::shared_ptr<Handler> quic_manager,
               std::shared_ptr<ClientContext> ctx,
               ConnectionID& id,
               std::shared_ptr<uv_udp_t> handle);

        ~Client();

        std::shared_ptr<Stream> open_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<uv_udp_t> get_handle(Address& addr) override;

        std::shared_ptr<uv_udp_t> get_handle(Path& p) override;

        inline Connection* accept_initial_connection(Packet& pkt, ConnectionID& dcid) override
        {
            log::warning(log_cat, "{} called (this should probably not be called)", __PRETTY_FUNCTION__);
            return nullptr;
        }

      private:
    };

}  // namespace oxen::quic
