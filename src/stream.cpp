#include "stream.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
#include "messages.hpp"
#include "result.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <exception>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace oxen::quic
{
    Stream::Stream(Connection& conn, Endpoint& _ep, stream_data_callback data_cb, stream_close_callback close_cb) :
            IOChannel{conn, _ep},
            reference_id{conn.reference_id()},
            data_callback{data_cb},
            close_callback{std::move(close_cb)}
    {
        log::trace(log_cat, "Creating Stream object...");

        if (!data_callback)
            data_callback = conn.get_default_data_callback();

        if (!close_callback)
            close_callback = [](Stream&, uint64_t error_code) {
                log::debug(log_cat, "Default stream close callback called ({})", quic_strerror(error_code));
            };

        log::trace(log_cat, "Stream object created");
    }

    Stream::~Stream()
    {
        log::trace(log_cat, "Destroying stream {}", _stream_id);
    }

    void Stream::set_watermark(
            size_t low, size_t high, std::optional<opt::watermark> low_cb, std::optional<opt::watermark> high_cb)
    {
        if (not low_cb and not high_cb)
            throw std::invalid_argument{"Must pass at least one callback in call to ::set_watermark()!"};

        endpoint.call_soon([this, low, high, low_hook = std::move(low_cb), high_hook = std::move(high_cb)]() {
            if (_is_closing || _is_shutdown || _sent_fin)
            {
                log::warning(log_cat, "Failed to set watermarks; stream is not active!");
                return;
            }

            _low_mark = low;
            _high_mark = high;

            if (low_hook.has_value())
                _low_water = std::move(*low_hook);
            else
                _low_water.clear();

            if (high_hook.has_value())
                _high_water = std::move(*high_hook);
            else
                _high_water.clear();

            _is_watermarked = true;

            log::trace(log_cat, "Stream set watermarks!");
        });
    }

    void Stream::clear_watermarks()
    {
        endpoint.call_soon([this]() {
            if (not _is_watermarked and not _low_water and not _high_water)
            {
                log::warning(log_cat, "Failed to clear watermarks; stream has none set!");
                return;
            }

            _low_mark = 0;
            _high_mark = 0;
            if (_low_water)
                _low_water.clear();
            if (_high_water)
                _high_water.clear();
            _is_watermarked = false;
            log::trace(log_cat, "Stream cleared currently set watermarks!");
        });
    }

    void Stream::pause()
    {
        endpoint.call([this]() {
            if (not _paused)
            {
                log::debug(log_cat, "Pausing stream ID:{}", _stream_id);
                assert(_paused_offset == 0);
                _paused = true;
            }
            else
                log::debug(log_cat, "Stream ID:{} already paused!", _stream_id);
        });
    }

    void Stream::resume()
    {
        endpoint.call([this]() {
            if (_paused)
            {
                log::debug(log_cat, "Resuming stream ID:{}", _stream_id);
                if (_paused_offset)
                {
                    ngtcp2_conn_extend_max_stream_offset(*_conn, _stream_id, _paused_offset);
                    _paused_offset = 0;
                }

                _paused = false;
            }
            else
                log::debug(log_cat, "Stream ID:{} is not paused!", _stream_id);
        });
    }

    bool Stream::is_paused() const
    {
        return endpoint.call_get([this]() { return _paused; });
    }

    bool Stream::available() const
    {
        return endpoint.call_get([this] { return !(_is_closing || _is_shutdown || _sent_fin); });
    }

    bool Stream::is_ready() const
    {
        return endpoint.call_get([this] { return _ready; });
    }

    bool Stream::has_watermarks() const
    {
        return endpoint.call_get([this]() { return _is_watermarked and _low_water and _high_water; });
    }

    std::shared_ptr<Stream> Stream::get_stream()
    {
        return shared_from_this();
    }

    void Stream::close(uint64_t app_err_code)
    {
        if (app_err_code > APP_ERRCODE_MAX)
            throw std::invalid_argument{"Invalid application error code (too large)"};

        // NB: this *must* be a call (not a call_soon) because Connection calls on a short-lived
        // Stream that won't survive a return to the event loop.
        endpoint.call([this, app_err_code]() {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (_is_shutdown)
                log::trace(log_cat, "Stream is already shutting down");
            else if (_is_closing)
                log::trace(log_cat, "Stream is already closing");
            else
            {
                _is_closing = _is_shutdown = true;
                if (_conn)
                {
                    log::info(log_cat, "Closing stream (ID: {}) with: {}", _stream_id, quic_strerror(app_err_code));
                    ngtcp2_conn_shutdown_stream(*_conn, 0, _stream_id, app_err_code);
                }
            }
            if (_is_shutdown)
                data_callback = nullptr;

            if (!_conn)
            {
                log::warning(log_cat, "Stream close ignored: the stream's connection is gone");
                return;
            }

            _conn->packet_io_ready();
        });
    }

    void Stream::closed(uint64_t app_code)
    {
        if (close_callback)
        {
            try
            {
                close_callback(*this, app_code);
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception in stream close callback: {}", e.what());
            }
        }

        _conn = nullptr;
        _is_closing = _is_shutdown = true;
    }

    void Stream::append_buffer(bspan buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        user_buffers.emplace_back(buffer, std::move(keep_alive));
        assert(endpoint.in_event_loop());
        assert(_conn);
        if (_ready)
            _conn->packet_io_ready();
        else
            log::debug(log_cat, "Stream not ready for broadcast yet, data appended to buffer and on deck");
    }

    void Stream::acknowledge(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Acking {} bytes of {}/{} unacked/size", bytes, _unacked_size, size());

        assert(bytes <= _unacked_size);
        _unacked_size -= bytes;

        // drop all acked user_buffers, as they are unneeded
        while (bytes >= user_buffers.front().first.size() && bytes)
        {
            bytes -= user_buffers.front().first.size();
            user_buffers.pop_front();
            log::trace(log_cat, "bytes: {}", bytes);
        }

        // advance bsv pointer to cover any remaining acked data
        if (bytes)
        {
            auto& front = user_buffers.front().first;
            front = front.subspan(bytes);
        }

        auto sz = size();

        // Do not bother with this block of logic if no watermarks are set
        if (_is_watermarked)
        {
            auto unsent = sz - _unacked_size;

            // We are above the high watermark. We prime the low water hook to be fired the next time we drop below the low
            // watermark. If the high water hook exists and is primed, execute it
            if (unsent >= _high_mark)
            {
                _low_primed = true;
                log::trace(log_cat, "Low water hook primed!");

                if (_high_water and _high_primed)
                {
                    log::debug(log_cat, "Executing high watermark hook!");
                    _high_primed = false;
                    return _high_water(*this);
                }
            }
            // We are below the low watermark. We prime the high water hook to be fired the next time we rise above the high
            // watermark. If the low water hook exists and is primed, execute it
            else if (unsent <= _low_mark)
            {
                _high_primed = true;
                log::trace(log_cat, "High water hook primed!");

                if (_low_water and _low_primed)
                {
                    log::debug(log_cat, "Executing low watermark hook!");
                    _low_primed = false;
                    return _low_water(*this);
                }
            }

            // Low/high watermarks were executed and self-cleared, so clean up
            if (not _high_water and not _low_water)
                return clear_watermarks();
        }

        log::trace(log_cat, "{} bytes acked, {} unacked remaining", bytes, sz);
    }

    void Stream::wrote(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Increasing _unacked_size by {}B", bytes);
        _unacked_size += bytes;
    }

    static auto get_buffer_it(std::deque<std::pair<bspan, std::shared_ptr<void>>>& bufs, size_t offset)
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

    void Stream::revert_stream()
    {
        assert(endpoint.in_event_loop());
        log::trace(log_cat, "Stream (ID:{}) reverting after early data rejected...", _stream_id);
        _unacked_size = 0;
        log::debug(log_cat, "Stream (ID:{}) has {}B in buffer, 0B unacked...", _stream_id, size());
    }

    std::vector<ngtcp2_vec> Stream::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::vector<ngtcp2_vec> nbufs{};

        log::trace(log_cat, "unsent: {}", unsent());

        if (user_buffers.empty() || unsent() == 0)
            return nbufs;

        auto [it, offset] = get_buffer_it(user_buffers, _unacked_size);
        nbufs.reserve(std::distance(it, user_buffers.end()));
        auto& temp = nbufs.emplace_back();
        temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data() + offset));
        temp.len = it->first.size() - offset;
        while (++it != user_buffers.end())
        {
            auto& temp = nbufs.emplace_back();
            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data()));
            temp.len = it->first.size();
        }

        return nbufs;
    }

    void Stream::send_impl(bspan data, std::shared_ptr<void> keep_alive)
    {
        if (data.empty())
            return;

        // If we aren't currently in the event loop then we need to keep a weak pointer to the
        // stream so that, when the below lambda gets processed, we can tell whether the stream is
        // still actually alive.  (But if we're already in the event loop the lambda fires
        // immediately and we don't want to have to do an extra refcount increment/decrement).
        std::optional<std::weak_ptr<Stream>> wself;
        if (!endpoint.in_event_loop())
            wself = weak_from_this();

        // In theory, `endpoint` that we use here might be inaccessible as well, but unlike conn
        // (which we have to check because it could have been closed by remote actions or network
        // events) the application has control and responsibility for keeping the network/endpoint
        // alive at least as long as all the Connections/Streams that instances that were attached
        // to it.
        endpoint.call([this, wself = std::move(wself), data, ka = std::move(keep_alive)]() {
            std::shared_ptr<Stream> sself;
            if (wself)
            {
                // send() was called from outside the event loop, so check to make sure the stream
                // is still alive (and thus `this` is still valid):
                if (!(sself = wself->lock()))
                {
                    log::debug(log_cat, "Stream has gone away, dropping send data");
                    return;
                }
            }
            // else send() was already inside the event loop and thus `this` is still valid

            if (_is_closing || _is_shutdown || _sent_fin)
            {
                log::debug(log_cat, "Stream {} is closing/shutting down, dropping send data", _stream_id);
                return;
            }
            else if (!_conn || _conn->is_closing() || _conn->is_draining())
            {
                log::debug(log_cat, "Stream {} unable to send: connection is closed", _stream_id);
                return;
            }
            log::trace(log_cat, "Stream (ID: {}) sending message: {}", _stream_id, buffer_printer{data});
            append_buffer(data, std::move(ka));
        });
    }

    size_t Stream::unsent_impl() const
    {
        log::trace(log_cat, "size={}, unacked={}", size(), unacked());
        return size() - unacked();
    }

    void Stream::set_ready(bool ready)
    {
        if (_ready == ready)
            return;

        log::debug(log_cat, "Setting stream {}", ready ? "ready" : "unready");
        _ready = ready;
        if (ready)
            on_ready();
        else
            on_unready();
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message)
    {
        log::trace(log_cat, "{}:{} -- {}", file, lineno, message);
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val)
    {
        log::trace(log_cat, "{}:{} -- {}{}", file, lineno, message, val);
    }

    std::optional<prepared_datagram> Stream::pending_datagram(bool)
    {
        log::warning(log_cat, "{} called, but this is a stream object!", __PRETTY_FUNCTION__);
        return std::nullopt;
    }

}  // namespace oxen::quic
