#include "stream.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
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
    void Stream::handle_opt(stream_data_callback data_cb)
    {
        data_callback = std::move(data_cb);
    }
    void Stream::handle_opt(stream_close_callback close_cb)
    {
        close_callback = std::move(close_cb);
    }
    void Stream::handle_opt(opt::stream_notify_t)
    {
        _notify = true;
        _had_notify = true;
    }
    void Stream::handle_opt(opt::stream_fin_callback fcb)
    {
        log::trace(log_cat, "{} fin callback", fcb.cb ? "Setting" : "Not setting (callback is nullptr)");
        fin_callback = std::move(fcb.cb);
    }
    Stream::Stream(Connection& conn, Endpoint& ep, base_ctor) : IOChannel{conn, ep}, reference_id{conn.reference_id()}
    {
        log::trace(log_cat, "Creating Stream object...");
    }
    void Stream::set_default_callbacks()
    {
        if (!data_callback)
            data_callback = _conn->get_default_data_callback();

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

    void Stream::enable_watermarks(
            size_t alarm, std::function<void(Stream&)> on_alarm, size_t clear, std::function<void(Stream&)> on_clear)
    {
        if (clear >= alarm)
            throw std::logic_error{
                    "Invalid enable_watermarks() call: alarm watermark ({}) must be > clear watermark ({})"_format(
                            alarm, clear)};
        loop.call_get([&] {
            if (_is_closing || _send_fin)
            {
                log::debug(log_cat, "Failed to set watermarks; stream is not active!");
                return;
            }

            if (!_watermarking)
                _watermark_alarm = false;
            // else leave it as-is
            _watermarking.emplace(alarm, clear);
            _watermark_on_alarm = std::move(on_alarm);
            _watermark_on_clear = std::move(on_clear);

            log::debug(
                    log_cat,
                    "Stream {} watermarks enabled ([{}, {}])",
                    _stream_id,
                    _watermarking->first,
                    _watermarking->second);

            // Invoke the check because the new limits might induce an immediate transition
            check_watermark();
        });
    }

    void Stream::disable_watermarks()
    {
        loop.call_get([this] {
            if (!_watermarking)
                return;
            _watermarking.reset();
            _watermark_alarm = false;
            _watermark_on_alarm = nullptr;
            _watermark_on_clear = nullptr;
            log::debug(log_cat, "Stream {} watermarking disabled", _stream_id);
        });
    }

    void Stream::pause()
    {
        loop.call_get([this]() {
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
        loop.call_get([this]() {
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
        return loop.call_get([this]() { return _paused; });
    }

    bool Stream::writable() const
    {
        return loop.call_get([this] { return !(_is_closing || _send_fin || _sent_fin); });
    }
    bool Stream::readable() const
    {
        return loop.call_get([this] { return !(_is_closing || _received_fin); });
    }

    bool Stream::is_ready() const
    {
        return loop.call_get([this] { return _ready; });
    }

    std::optional<bool> Stream::watermark_status() const
    {
        return loop.call_get([this]() -> std::optional<bool> {
            if (!_watermarking)
                return std::nullopt;
            return _watermark_alarm;
        });
    }

    void Stream::on_fin()
    {
        _received_fin = true;
        if (fin_callback)
            fin_callback(*this);
    }

    void Stream::send_fin()
    {
        loop.call([this] {
            _send_fin = true;
            _conn->packet_io_ready();
        });
    }

    void Stream::close(uint64_t app_err_code)
    {
        if (app_err_code > APP_ERRCODE_MAX)
            throw std::invalid_argument{"Invalid application error code (too large)"};

        // NB: this *must* be a call (not a call_soon) because Connection calls on a short-lived
        // Stream that won't survive a return to the event loop.
        loop.call([this, app_err_code]() {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (_is_closing)
                log::trace(log_cat, "Stream is already closing");
            else
            {
                _send_fin = _is_closing = true;
                if (_conn)
                {
                    log::info(log_cat, "Closing stream (ID: {}) with: {}", _stream_id, quic_strerror(app_err_code));
                    ngtcp2_conn_shutdown_stream(*_conn, 0, _stream_id, app_err_code);
                }
            }
            data_callback = nullptr;

            if (!_conn)
            {
                log::debug(log_cat, "Stream close ignored: the stream's connection is gone");
                return;
            }

            _conn->packet_io_ready();
        });
    }

    void Stream::set_data_callback(stream_data_callback cb)
    {
        loop.call_get([&] { data_callback = std::move(cb); });
    }
    void Stream::set_close_callback(stream_close_callback cb)
    {
        loop.call_get([&] { close_callback = std::move(cb); });
    }
    void Stream::set_fin_callback(std::function<void(Stream&)> cb)
    {
        loop.call_get([&] { fin_callback = std::move(cb); });
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
        _send_fin = _is_closing = true;
    }

    void Stream::check_watermark()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        const auto& [alarm_thresh, clear_thresh] = *_watermarking;
        const size_t threshold = _unacked_size + (_watermark_alarm ? clear_thresh + 1 : alarm_thresh);
        size_t sum = 0;
        for (auto it = user_buffers.begin(); sum < threshold && it != user_buffers.end(); ++it)
            sum += it->first.size();
        if (_watermark_alarm)
        {
            if (sum < threshold)
            {
                log::debug(log_cat, "Watermark ({} unsent) dropped <= clear threshold ({})", sum, clear_thresh);
                _watermark_alarm = false;
                if (_watermark_on_clear)
                    _watermark_on_clear(*this);
            }
        }
        else if (sum >= threshold)
        {
            // "at least" because the sum above terminates early if we met the threshold
            log::debug(log_cat, "Watermark triggered alarm threshold ({}+ unsent >= alarm threshold {})", sum, alarm_thresh);
            _watermark_alarm = true;
            if (_watermark_on_alarm)
                _watermark_on_alarm(*this);
        }
    }

    void Stream::append_buffer(std::span<const std::byte> buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(loop.inside());
        assert(_conn);

        user_buffers.emplace_back(buffer, std::move(keep_alive));
        if (_watermarking)
            check_watermark();

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

        // Drop all fully-acked buffers that are no longer needed
        while (bytes && bytes >= user_buffers.front().first.size())
        {
            bytes -= user_buffers.front().first.size();
            user_buffers.pop_front();
            log::trace(log_cat, "bytes: {}", bytes);
        }

        // Any remaining acked bytes are the leading bytes of the first buffer, so chop them off:
        if (bytes)
        {
            auto& front = user_buffers.front().first;
            front = front.subspan(bytes);
        }

#ifndef NDEBUG
        log::trace(log_cat, "{} bytes acked, {} unacked remaining", bytes, size());
#endif
    }

    void Stream::wrote(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Increasing _unacked_size by {}B", bytes);
        _unacked_size += bytes;
        if (_notify)
            _notify = false;
        if (_watermarking)
            check_watermark();
    }

    static auto get_buffer_it(std::deque<std::pair<std::span<const std::byte>, std::shared_ptr<void>>>& bufs, size_t offset)
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
        assert(loop.inside());
        log::trace(log_cat, "Stream (ID:{}) reverting after early data rejected...", _stream_id);
        _unacked_size = 0;
        if (_had_notify)
            _notify = true;
        log::debug(log_cat, "Stream (ID:{}) has {}B in buffer, 0B unacked...", _stream_id, size());
    }

    std::pair<std::vector<ngtcp2_vec>, bool> Stream::pending(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::pair<std::vector<ngtcp2_vec>, bool> ret;
        auto& [nbufs, more] = ret;

        log::trace(log_cat, "unsent: {}", unsent());

        if (user_buffers.empty() || unsent() == 0)
        {
            if (_notify)
            {
                // If this is still set it means the stream is configured to notify the other end,
                // and we haven't done so yet, so return an empty buffer.
                nbufs.emplace_back(nullptr, 0);
            }
            more = false;
            return ret;
        }

        auto [it, offset] = get_buffer_it(user_buffers, _unacked_size);
        auto& temp = nbufs.emplace_back();
        temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data() + offset));
        temp.len = it->first.size() - offset;
        size_t total = temp.len;
        for (++it; it != user_buffers.end() && total < bytes; ++it)
        {
            auto& temp = nbufs.emplace_back();
            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data()));
            temp.len = it->first.size();
            total += temp.len;
        }

        more = it != user_buffers.end();
        return ret;
    }

    void Stream::send_impl(std::span<const std::byte> data, std::shared_ptr<void> keep_alive)
    {
        if (data.empty())
            return;

        // If we aren't currently in the event loop then we need to keep a weak pointer to the
        // stream so that, when the below lambda gets processed, we can tell whether the stream is
        // still actually alive.  (But if we're already in the event loop the lambda fires
        // immediately and we don't want to have to do an extra refcount increment/decrement).
        std::optional<std::weak_ptr<Stream>> wself;
        if (!loop.inside())
            wself = weak_from_this();

        // In theory, `endpoint` that we use here might be inaccessible as well, but unlike conn
        // (which we have to check because it could have been closed by remote actions or network
        // events) the application has control and responsibility for keeping the network/endpoint
        // alive at least as long as all the Connections/Streams that instances that were attached
        // to it.
        loop.call([this, wself = std::move(wself), data, ka = std::move(keep_alive)]() {
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

            if (_is_closing || _send_fin || _sent_fin)
            {
                log::debug(log_cat, "Stream {} is already finalized, dropping send data", _stream_id);
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

}  // namespace oxen::quic
