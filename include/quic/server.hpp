#pragma once

#include "context.hpp"
#include "endpoint.hpp"
#include "stream.hpp"
#include "handler.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw.hpp>

#include <cstddef>
#include <memory>
#include <stdlib.h>


namespace oxen::quic
{	
	class Server : public Endpoint
	{
		public:
            std::shared_ptr<ServerContext> context;

			Server(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ServerContext> ctx) : 
                Endpoint{quic_manager},
                context{ctx}
			{
                log::trace(log_cat, "Successfully created Server endpoint");
            }

            ~Server();

            std::shared_ptr<uvw::UDPHandle>
            get_handle(Address& addr) override;

            std::shared_ptr<uvw::UDPHandle>
            get_handle(Path& p) override;

		protected:
			std::shared_ptr<Connection>
			accept_initial_connection(Packet& pkt, ConnectionID& dcid) override;

	};

}	// namespace oxen::quic
