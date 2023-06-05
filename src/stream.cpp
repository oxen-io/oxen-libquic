#include "stream.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
}

#include <cstddef>
#include <cstdio>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"

namespace oxen::quic
{
    Stream::Stream(Connection& conn, stream_data_callback_t data_cb, stream_close_callback_t close_cb, int64_t stream_id) :
            conn{conn}, stream_id{stream_id}, data_callback{data_cb}
    {
        log::trace(log_cat, "Creating Stream object...");

        close_callback = (close_cb) ? std::move(close_cb) : [](Stream& s, uint64_t error_code) {
            log::warning(log_cat, "Stream close callback called (error code: {})", error_code);
        };

        log::trace(log_cat, "Stream object created");
    }

    Stream::Stream(Connection& conn, int64_t stream_id) : Stream{conn, nullptr, nullptr, stream_id} {}

    Stream::~Stream()
    {
        log::debug(log_cat, "Destroying stream {}", stream_id);

        bool was_closing = is_closing;
        is_closing = is_shutdown = true;

        if (!was_closing && close_callback)
            close_callback(*this, STREAM_ERROR_CONNECTION_EXPIRED);
    }

    Connection& Stream::get_conn()
    {
        return conn;
    }

    void Stream::close(uint64_t error_code)
    {
        conn.quic_manager->call([this, error_code]() {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (is_shutdown)
                log::info(log_cat, "Stream is already shutting down");
            else if (is_closing)
                log::debug(log_cat, "Stream is already closing");
            else
            {
                is_closing = is_shutdown = true;
                log::info(log_cat, "Closing stream (ID: {}) with error code {}", stream_id, ngtcp2_strerror(error_code));
                ngtcp2_conn_shutdown_stream(conn, 0, stream_id, error_code);
            }
            if (is_shutdown)
                data_callback = nullptr;

            conn.io_ready();
        });
    }

    void Stream::append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        user_buffers.emplace_back(buffer, std::move(keep_alive));
        if (ready)
            conn.io_ready();
        else
            log::info(log_cat, "Stream not ready for broadcast yet, data appended to buffer and on deck");
    }

    void Stream::acknowledge(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Acking {} bytes of {}/{} unacked/size", bytes, unacked_size, size());

        assert(bytes <= unacked_size);
        unacked_size -= bytes;

        // drop all acked user_buffers, as they are unneeded
        while (bytes >= user_buffers.front().first.size() && bytes)
        {
            bytes -= user_buffers.front().first.size();
            user_buffers.pop_front();
            log::trace(log_cat, "bytes: {}", bytes);
        }

        // advance bsv pointer to cover any remaining acked data
        if (bytes)
            user_buffers.front().first.remove_prefix(bytes);

        log::trace(log_cat, "{} bytes acked, {} unacked remaining", bytes, size());
    }

    void Stream::wrote(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Increasing unacked_size by {}B", bytes);
        unacked_size += bytes;
    }

    static auto get_buffer_it(std::deque<std::pair<bstring_view, std::shared_ptr<void>>>& bufs, size_t offset)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto it = bufs.begin();

        while (offset >= it->first.size() && it != bufs.end() && offset)
        {
            offset -= it->first.size();
            it++;
        }

        return std::make_pair(std::move(it), offset);
    }

    std::vector<ngtcp2_vec> Stream::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::vector<ngtcp2_vec> nbufs{};

        log::trace(log_cat, "unsent: {}", unsent());

        if (user_buffers.empty() || unsent() == 0)
            return nbufs;

        auto [it, offset] = get_buffer_it(user_buffers, unacked_size);
        nbufs.reserve(std::distance(it, user_buffers.end()));
        auto& temp = nbufs.emplace_back();
        temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data() + offset));
        temp.len = it->first.size() - offset;
        while (++it != user_buffers.end())
        {
            log::trace(log_cat, "call F");
            auto& temp = nbufs.emplace_back();
            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data()));
            temp.len = it->first.size();
        }

        return nbufs;
    }

    void Stream::send(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        conn.quic_manager->call([this, data, keep_alive]() {
            log::trace(log_cat, "Stream (ID: {}) sending message: {}", stream_id, buffer_printer{data});
            append_buffer(data, keep_alive);
        });
    }

    void Stream::set_user_data(std::shared_ptr<void> data)
    {
        conn.quic_manager->call([this, data]() { user_data = std::move(data); });
    }
}  // namespace oxen::quic
