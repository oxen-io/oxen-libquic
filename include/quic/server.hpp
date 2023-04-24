#pragma once

#include "endpoint.hpp"
#include "stream.hpp"
#include "handler.hpp"

#include <cstddef>
#include <memory>
#include <stdlib.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw/async.h>
#include <uvw/timer.h>
#include <uvw/poll.h>


namespace oxen::quic
{
	using stream_open_cb = std::function<bool(Stream& stream, std::string remote_addr, uint16_t remote_port)>;
	
	class Server : public Endpoint
	{
		public:
			Server(Handler& endpoint) : Endpoint{endpoint}
			{ default_stream_bufsize = 0; }

			stream_open_cb stream_open_callback;

		private:

			std::shared_ptr<Connection>
			accept_initial_connection(const Packet& pkt) override;

	};

}	// namespace oxen::quic
