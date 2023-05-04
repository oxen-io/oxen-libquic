#pragma once

#include "endpoint.hpp"
#include "handler.hpp"
#include "stream.hpp"
#include "utils.hpp"

#include <cstddef>
#include <memory>
#include <stdlib.h>
#include <string_view>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw.hpp>


namespace oxen::quic
{
    class ClientContext;
    
    class Client : public Endpoint
    {
        public:
            std::shared_ptr<ClientContext> context;

            Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx, ConnectionID& id, std::shared_ptr<uvw::UDPHandle> handle);
            ~Client();

            std::shared_ptr<Stream>
            open_stream(size_t bufsize, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

            std::shared_ptr<uvw::UDPHandle>
            get_handle(Address& addr) override;

            std::shared_ptr<uvw::UDPHandle>
            get_handle(Path& p) override;

            // void
            // install_stream_forwarding(Stream& s, bstring_view data) override;

            inline std::shared_ptr<Connection>
            accept_initial_connection(Packet& pkt) override 
            {
                fprintf(stderr, "%s called (this should probably not be called)\n", __PRETTY_FUNCTION__); 
                return nullptr;
            }

        private:

    };

}   // namespace oxen::quic
