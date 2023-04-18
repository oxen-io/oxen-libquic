#include "stream.hpp"
#include "connection.hpp"

#include <cstddef>
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


    Stream::Stream(
        Connection& conn, data_callback_t data_cb, close_callback_t close_cb, size_t bufsize, int64_t stream_id) :
        data_callback{std::move(data_cb)},
        close_callback{std::move(close_cb)},
        conn{conn},
        stream_id{stream_id},
        buf{bufsize} 
    {
        avail_trigger->on<uvw::AsyncEvent>([this](auto&, auto&) { handle_unblocked(); });
    }


    Stream::Stream(Connection& conn, int64_t stream_id, size_t bufsize) :
        Stream{conn, nullptr, nullptr, bufsize, stream_id}
    {}


    Stream::~Stream()
    {
        fprintf(stderr, "Destroying stream %lu\n", stream_id);
        if (avail_trigger)
        {
            avail_trigger->close();
            avail_trigger.reset();
        }
        bool was_closing = is_closing;
        is_closing = is_shutdown = true;
        if (!was_closing && close_callback)
            close_callback(*this, STREAM_ERROR_CONNECTION_EXPIRED);
    }


    Connection&
    Stream::get_conn()
    {
        return conn;
    }


	void
	Stream::close(uint64_t error_code)
    {
        fprintf(stderr, "Closing stream (ID: %li) with error code ", stream_id);
        fprintf(stderr, "%s\n", (error_code != 0) ? 
            std::to_string(error_code).c_str() : 
            "[NONE]");

        if (is_shutdown || is_closing)
        {
            fprintf(stderr, "Stream is already: ");
            fprintf(stderr, "%s", (is_closing) ? "[closing]" : "[not closing]");
            fprintf(stderr, " and %s\n", (is_shutdown) ? "[shutdown]" : "[not shutdown]");;
        }
        if (error_code)
        {
            is_closing = is_shutdown = true;
            ngtcp2_conn_shutdown_stream(conn, stream_id, error_code);
        }
        if (is_shutdown)
            data_callback = {};

        conn.io_ready();
    }


    auto
    get_buffer_it(
        std::deque<std::pair<std::unique_ptr<const std::byte[]>, size_t>>& bufs, size_t offset)
    {
        auto it = bufs.begin();
        while (offset >= it->second)
        {
            offset -= it->second;
            it++;
        }
        return std::make_pair(std::move(it), offset);
    }


    void
    Stream::append_buffer(const std::byte* buffer, size_t length)
    {
        assert(this->buf.empty());
        user_buffers.emplace_back(buffer, length);
        size += length;
        conn.io_ready();
    }


    void
    Stream::acknowledge(size_t bytes)
    {
        assert(bytes <= unacked_size && unacked_size <= size);

        fprintf(stderr, "Acked %lu bytes of %lu/%lu unacked/total\n", bytes, unacked_size, size);

        unacked_size -= bytes;
        size -= bytes;
        if (!buf.empty())
            start = size == 0 ? 0 : (start + bytes) % buf.size();  // reset start to 0 (to reduce wrapping buffers) if empty
        else if (size == 0)
        {
            user_buffers.clear();
            start = 0;
        }
        else
        {
            while (bytes)
            {
                assert(!user_buffers.empty());
                assert(start < user_buffers.front().second);
                if (size_t remaining = user_buffers.front().second - start; bytes >= remaining)
                {
                    user_buffers.pop_front();
                    start = 0;
                    bytes -= remaining;
                }
                else
                {
                    start += bytes;
                    bytes = 0;
                }
            }
        }
    }


    void
    Stream::when_available(unblocked_callback_t unblocked_cb)
    {
        assert(available() == 0);
        unblocked_callbacks.push(std::move(unblocked_cb));
    }


    void
    Stream::handle_unblocked()
    {
        if (is_closing)
            return;
        if (buf.empty())
        {
            while (!unblocked_callbacks.empty() && unblocked_callbacks.front()(*this))
                unblocked_callbacks.pop();
        }
        while (!unblocked_callbacks.empty() && available() > 0)
        {
            if (unblocked_callbacks.front()(*this))
                unblocked_callbacks.pop();
            else
                assert(available() == 0);
        }

        conn.io_ready();
    }


    void
    Stream::io_ready()
    {
        conn.io_ready();
    }


    void
    Stream::available_ready()
    {
        if (avail_trigger)
            avail_trigger->send();
    }


    void
    Stream::wrote(size_t bytes)
    {
        assert(bytes <= unsent());
        unacked_size += bytes;
    }


    std::vector<bstring>
    Stream::pending()
    {
        std::vector<bstring> bufs;
        size_t rsize = unsent();
        if (!rsize)
            return bufs;
        if (!buf.empty())
        {
            size_t rpos = (start + unacked_size) % buf.size();
            if (size_t rend = rpos + rsize; rend <= buf.size())
            {
                bufs.emplace_back(buf.data() + rpos, rsize);
            }
            else
            {  // wrapping
                bufs.reserve(2);
                bufs.emplace_back(buf.data() + rpos, buf.size() - rpos);
                bufs.emplace_back(buf.data(), rend % buf.size());
            }
        }
        else
        {
            assert(!user_buffers.empty());  // If empty then unsent() should have been 0
            auto [it, offset] = get_buffer_it(user_buffers, start + unacked_size);
            bufs.reserve(std::distance(it, user_buffers.end()));
            assert(it != user_buffers.end());
            bufs.emplace_back(it->first.get() + offset, it->second - offset);
            for (++it; it != user_buffers.end(); ++it)
                bufs.emplace_back(it->first.get(), it->second);
        }

        return bufs;
    }


    void
    Stream::data(std::shared_ptr<void> data)
    {
        user_data = std::move(data);
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
