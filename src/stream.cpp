#include "stream.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
}

#include <cstddef>
#include <cstdio>
#include <stdexcept>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
#include "network.hpp"
#include "types.hpp"

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
                log::info(log_cat, "Default stream close callback called ({})", quic_strerror(error_code));
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

            log::info(log_cat, "Stream set watermarks!");
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
            log::info(log_cat, "Stream (ID:{}) cleared currently set watermarks!", _stream_id);
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
                    ngtcp2_conn_extend_max_offset(*_conn, _paused_offset);
                    _paused_offset = 0;
                }

                _paused = false;
            }
            else
                log::debug(log_cat, "Stream ID:{} is not paused!", _stream_id);
        });
    }

    void Stream::set_remote_reset_hooks(opt::remote_stream_reset sr)
    {
        // we can use ::call(...) instead of ::call_soon(...) because stream read/write shutdown only happens once per stream
        // lifetime, and the application would be beyond incorrect to invoke this function in the callbacks themselves
        endpoint.call([this, hooks = std::move(sr)]() {
            if (_in_reset)
                throw std::runtime_error{"Cannot set `remote_stream_reset` while executing currently set hooks!!"};

            log::debug(log_cat, "Stream (ID:{}) provided `remote_stream_reset` hooks!", _stream_id);
            _remote_reset = std::move(hooks);
        });
    }

    void Stream::clear_remote_reset_hooks()
    {
        // we can use ::call(...) instead of ::call_soon(...) because stream read/write shutdown only happens once per stream
        // lifetime, and the application would be beyond incorrect to invoke this function in the callbacks themselves
        endpoint.call([this]() {
            if (_in_reset)
                throw std::runtime_error{"Cannot set `remote_stream_reset` while executing currently set hooks!!"};

            log::debug(log_cat, "Stream (ID:{}) cleared `remote_stream_reset` hooks!", _stream_id);
            _remote_reset.clear();
            assert(not _remote_reset);
        });
    }

    bool Stream::has_remote_reset_hooks() const
    {
        return endpoint.call_get(
                [this]() { return _remote_reset.has_stop_sending_hook() or _remote_reset.has_stream_reset_hook(); });
    }

    void Stream::stop_sending(uint64_t code)
    {
        endpoint.call([this, code]() {
            if (not _is_reading)
            {
                log::warning(log_cat, "Stream (ID:{}) has already halted read operations!", _stream_id);
                return;
            }

            _is_reading = false;

            log::critical(log_cat, "Halting all read operations on stream ID:{}!", _stream_id);
            ngtcp2_conn_shutdown_stream_read(*_conn, 0, _stream_id, code);
        });
    }

    void Stream::reset_stream(uint64_t code)
    {
        endpoint.call([this, code]() {
            if (not _is_writing)
            {
                log::warning(log_cat, "Stream (ID:{}) has already halted write operations!", _stream_id);
                return;
            }

            auto sz = size();

            if (sz == 0)
            {
                log::critical(
                        log_cat,
                        "All transmitted data dispatched (unacked:{}) and acked; halting all write operations on stream "
                        "ID:{} (ec:{})",
                        _unacked_size,
                        _stream_id,
                        code);
                ngtcp2_conn_shutdown_stream_write(*_conn, 0, _stream_id, code);
                return;
            }

            log::critical(
                    log_cat,
                    "Stream deferring writing shutdown (ec:{}) until output buffers cleared (size:{})...",
                    code,
                    sz);
            // if buffers are empty and we call shutdown_stream_write now, we do not need to flip this boolean; it is used to
            // signal for the same call in ::acknowledge()
            _is_writing = false;
            // set the code we wanted to pass to to ngtcp2_conn_shutdown_stream_write for later use
            _deferred_ec = code;
        });
    }

    void Stream::stop_reading()
    {
        endpoint.call([this]() { stop_sending(STREAM_REMOTE_READ_SHUTDOWN); });
    }

    void Stream::stop_writing()
    {
        endpoint.call([this]() { reset_stream(STREAM_REMOTE_WRITE_SHUTDOWN); });
    }

    bool Stream::is_paused() const
    {
        return endpoint.call_get([this]() { return _paused; });
    }

    bool Stream::is_reading() const
    {
        return endpoint.call_get([this]() { return _is_reading; });
    }

    bool Stream::is_writing() const
    {
        return endpoint.call_get([this]() { return _is_writing; });
    }

    std::shared_ptr<connection_interface> Stream::get_conn_interface()
    {
        return std::static_pointer_cast<connection_interface>(_conn->shared_from_this());
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
                log::info(log_cat, "Stream is already shutting down");
            else if (_is_closing)
                log::debug(log_cat, "Stream is already closing");
            else
            {
                _is_closing = _is_shutdown = true;

                // TOFIX: DISCUSS: testing this
                _is_reading = _is_writing = false;

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

    void Stream::append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (not _is_writing)
        {
            log::warning(log_cat, "Stream (ID:{}) has halted writing; payload NOT appended to buffer!", _stream_id);
            return;
        }

        user_buffers.emplace_back(buffer, std::move(keep_alive));
        assert(endpoint.in_event_loop());
        assert(_conn);
        if (_ready)
            _conn->packet_io_ready();
        else
            log::info(log_cat, "Stream not ready for broadcast yet, data appended to buffer and on deck");

        if (_is_watermarked)
        {
            // We are above the high watermark. We prime the low water hook to be fired the next time we drop below the low
            // watermark. If the high water hook exists and is primed, execute it
            // if (auto unsent = size() - _unacked_size; unsent >= _high_mark)
            if (size() >= _high_mark)
            {
                if (not _low_primed)
                {
                    _low_primed = true;
                    log::debug(log_cat, "Low water hook primed!");
                }

                if (_high_water and _high_primed)
                {
                    log::debug(log_cat, "Executing high watermark hook!");
                    _high_primed = false;
                    _high_water(*this);
                }
            }

            // Low/high watermarks were executed and self-cleared, so clean up
            if (not _high_water and not _low_water)
                return clear_watermarks();
        }
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
            user_buffers.front().first.remove_prefix(bytes);

        if (not _is_writing and user_buffers.empty())
        {
            log::warning(
                    log_cat,
                    "All transmitted data dispatched (unacked:{}) and acked; halting all write operations on stream ID:{} "
                    "(ec:{})",
                    _unacked_size,
                    _stream_id,
                    _deferred_ec);
            ngtcp2_conn_shutdown_stream_write(*_conn, 0, _stream_id, _deferred_ec);
            return;
        }

        auto sz = size();

        // Do not bother with this block of logic if no watermarks are set
        if (_is_watermarked)
        {
            // We are below the low watermark. We prime the high water hook to be fired the next time we rise above the high
            // watermark. If the low water hook exists and is primed, execute it
            if (sz <= _low_mark)
            {
                if (not _high_primed)
                {
                    _high_primed = true;
                    log::debug(log_cat, "High water hook primed!");
                }

                if (_low_water and _low_primed)
                {
                    log::debug(log_cat, "Executing low watermark hook!");
                    _low_primed = false;
                    _low_water(*this);
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

    void Stream::send_impl(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        if (data.empty())
            return;

        // In theory, `endpoint` that we use here might be inaccessible as well, but unlike conn
        // (which we have to check because it could have been closed by remote actions or network
        // events) the application has control and responsibility for keeping the network/endpoint
        // alive at least as long as all the Connections/Streams that instances that were attached
        // to it.
        endpoint.call([this, data, ka = std::move(keep_alive)]() {
            if (!_conn || _conn->is_closing() || _conn->is_draining())
            {
                log::warning(log_cat, "Stream {} unable to send: connection is closed", _stream_id);
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

    void Stream::set_ready()
    {
        log::trace(log_cat, "Setting stream ready");
        _ready = true;
        on_ready();
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message)
    {
        log::trace(log_cat, "{}:{} -- {}", file, lineno, message);
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val)
    {
        log::trace(log_cat, "{}:{} -- {}{}", file, lineno, message, val);
    }

    prepared_datagram Stream::pending_datagram(bool)
    {
        log::warning(log_cat, "{} called, but this is a stream object!", __PRETTY_FUNCTION__);
        throw std::runtime_error{"Stream objects should not be queried for pending datagrams!"};
    }

}  // namespace oxen::quic
