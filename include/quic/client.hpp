#pragma once

#include "endpoint.hpp"

#include <cstddef>
#include <stdlib.h>
#include <string_view>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw/async.h>
#include <uvw/timer.h>
#include <uvw/poll.h>


namespace oxen::quic
{
    class Client : public Endpoint
    {
        public:
            Client(
                Tunnel& tun_endpoint, const uint16_t remote_port, Address&& remote);

        private:
            size_t
            write_packet_header(uint16_t remote_port, uint8_t ecn) override;
    };

}   // namespace oxen::quic
