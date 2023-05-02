#pragma once

#include "endpoint.hpp"
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

            Client(std::shared_ptr<Handler> quic_manager, const uint16_t remote_port, Address& remote, Address& local);

            Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx, ConnectionID& id);

            std::pair<ConnectionID&, std::shared_ptr<Connection>>
            make_conn(Address& remote, Address& local);

        private:

    };

}   // namespace oxen::quic
