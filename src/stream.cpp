#include "stream.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "connection.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <cstdio>


namespace oxen::quic
{
    size_t
    DatagramBuffer::write(const char* data, size_t nbits)
    {
        // ensure we have enough space to write to buffer
        assert(remaining >= nbits);
        // write to buffer
        std::memcpy(&buf[nwrote], data, nbits);
        // update counters
        nwrote += nbits;
        remaining -= nbits;

        return nbits;
    }


    Stream::Stream(
        Connection& conn, size_t bufsize, stream_data_callback_t data_cb, stream_close_callback_t close_cb, int64_t stream_id) :
        conn{conn},
        stream_id{stream_id},
        max_bufsize{bufsize},
        avail_trigger{conn.quic_manager->loop()->resource<uvw::AsyncHandle>()}
    {
        data_callback = (data_cb) ? 
            std::move(data_cb) : 
            [](Stream& s, bstring_view data) {
                auto handle = s.udp_handle;
                Packet pkt{.path = Path{handle->sock(), handle->peer()}, .data = data};
                s.conn.endpoint->handle_packet(pkt);};
        close_callback = (close_cb) ? 
            std::move(close_cb) : 
            [](Stream& s, uint64_t error_code) {
                fprintf(stderr, "Error: %lu", error_code);
                s.close(error_code);};

        fprintf(stderr, "Creating Stream object...\n");
        avail_trigger->on<uvw::AsyncEvent>([this](auto&, auto&) { handle_unblocked(); });
        udp_handle = conn.endpoint->get_handle(conn.local);
        fprintf(stderr, "Stream object created\n");
    }


    Stream::Stream(Connection& conn, size_t bufsize, int64_t stream_id) :
        Stream{conn, bufsize, nullptr, nullptr, stream_id}
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
        std::deque<std::pair<bstring_view, std::any>>& bufs, size_t offset)
    {
        auto it = bufs.begin();
        while (offset >= sizeof(it->second))
        {
            offset -= sizeof(it->second);
            it++;
        }
        return std::make_pair(std::move(it), offset);
    }


    void
    Stream::append_buffer(const std::byte* buffer, size_t length)
    {
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
        if (size == 0)
        {
            user_buffers.clear();
            start = 0;
        }
        else
        {
            while (bytes)
            {
                assert(!user_buffers.empty());
                assert(start < sizeof(user_buffers.front()));
                if (size_t remaining = sizeof(user_buffers.front()) - start; bytes >= remaining)
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


    std::vector<bstring_view>
    Stream::pending()
    {
        std::vector<bstring_view> bufs;
        size_t rsize = unsent();
        if (!rsize)
            return bufs;
        else
        {
            assert(!user_buffers.empty());  // If empty then unsent() should have been 0
            auto [it, offset] = get_buffer_it(user_buffers, start + unacked_size);
            bufs.reserve(std::distance(it, user_buffers.end()));
            assert(it != user_buffers.end());
            bufs.emplace_back(it->first.begin() + offset, sizeof(it->second) - offset);
            for (++it; it != user_buffers.end(); ++it)
                bufs.emplace_back(it->first.begin(), sizeof(it->second));
        }

        return bufs;
    }


    void
    Stream::send(bstring_view data, std::any keep_alive)
    {
        unacked_size += data.size();
        
        udp_handle->send(
            conn.remote, const_cast<char*>(reinterpret_cast<const char*>(data.data())), data.length());
    }


    void
    Stream::set_user_data(std::shared_ptr<void> data)
    {
        user_data = std::move(data);
    }
}   // namespace oxen::quic
