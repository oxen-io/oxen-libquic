#include "stream.hpp"

#include <cstdio>
#include <ngtcp2/ngtcp2.h>


namespace oxen::quic
{
    size_t
    DatagramBuffer::write(const char* data, size_t nbits)
    {
        /// ensure we have enough space to write to buffer
        assert(remaining >= nbits);
        /// write to buffer
        std::memcpy(&buf[nwrote], data, nbits);
        /// update counters
        nwrote += nbits;
        remaining -= nbits;

        return nbits;
    }
    

    std::shared_ptr<Stream> 
	Stream::quic_stream_create(ngtcp2_conn* connection)
    {
        auto new_stream = std::make_shared<Stream>();
        new_stream.get()->conn = connection;
        
        if (ngtcp2_conn_open_bidi_stream(new_stream->conn, &new_stream->stream_id, &new_stream->data))
        {
            fprintf(stderr, "Erorr: unable to open new bidi stream");
            return nullptr;
        }

        return new_stream;
    }


    void quic_stream_destroy(Stream* stream) 
    {
        // Clean up the QUIC stream
        // ...
    }


    int quic_stream_send(Stream* stream, const void *data, size_t data_len) 
    {
        // Send data through the QUIC stream
        // ...
        return 0;
    }
}   // namespace oxen::quic
