#pragma once

#include "utils.hpp"

#include <cassert>
#include <memory>
#include <ngtcp2/ngtcp2.h>

#include <stddef.h>
#include <stdint.h>
#include <vector>


namespace oxen::quic
{
	///	One-shot datagram sent inside a quic connection
	struct DatagramBuffer
	{
		public:
			///	Write buffer for outgoing packets
			std::vector<std::byte> buf;

            /// Returns number of bits written to buffer
			size_t
			size() const { return buf.size(); }

			explicit DatagramBuffer(size_t size = 1200)
			{
				buf.reserve(size);
                nwrote = 0;
                remaining = size;
			}

			~DatagramBuffer()
			{
				std::memset(&buf, 0, buf.size());
                buf.clear();
			}

			DatagramBuffer&
			operator=(const DatagramBuffer& d)
			{
                assert(d.size() <= size());
                std::memcpy(buf.data(), d.buf.data(), d.size());
                return *this;
			}

            size_t
            write(const char* data, size_t nbits);

		private:
			///	Bits written to buffer
			size_t nwrote;
            size_t remaining;
	};

	///	Base stream class with information universal to uni/bidi derived classes
	class Stream
	{
		private:

		public:
			ngtcp2_conn *conn;
			int64_t stream_id;
			const uint8_t *data;
			size_t datalen;
			size_t nwrite;
			
			std::shared_ptr<Stream> 
			quic_stream_create(ngtcp2_conn* connection);
	};

	void quic_stream_destroy(Stream* stream);
	int quic_stream_send(Stream* stream, const void *data, size_t data_len);

}	// namespace oxen::quic
