#pragma once

#include "endpoint.hpp"

#include <cstddef>
#include <stdlib.h>
#include <string_view>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw.hpp>


namespace oxen::quic
{
    class Client : public Endpoint
    {
        public:
            Client(
                Handler& handler, const uint16_t remote_port, Address& remote, Address& local);

            Client(
                Handler& handler);

            ConnectionID
            make_conn(const uint16_t remote_port, Address& remote, Address& local);

        private:

    };

}   // namespace oxen::quic
