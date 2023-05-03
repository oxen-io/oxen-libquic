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
    /*
        TODO:
            - revisit if connection linking in Server::accept_initial_connection is needed, as it is done
              in the Connection constructor
    */

	using stream_open_cb = std::function<bool(Stream& stream, std::string remote_addr, uint16_t remote_port)>;
	
	class Server : public Endpoint
	{
		public:
            std::shared_ptr<ServerContext> context;

			Server(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ServerContext> ctx) : Endpoint{quic_manager}
			{
                default_stream_bufsize = 0;
                context = ctx;
            }

			stream_open_cb stream_open_callback;

		private:
			std::shared_ptr<Connection>
			accept_initial_connection(const Packet& pkt) override;

	};

}	// namespace oxen::quic
