#pragma once

#include "connection_ids.hpp"
#include "iochannel.hpp"
#include "opt.hpp"
#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace oxen::quic
{
    class Stream;
    class Endpoint;
    class Connection;

    // Stream callbacks
    using stream_data_callback = std::function<void(Stream&, std::span<const std::byte>)>;
    using stream_close_callback = std::function<void(Stream&, uint64_t error_code)>;
    using stream_constructor_callback =
            std::function<std::shared_ptr<Stream>(Connection&, Endpoint&, std::optional<int64_t>)>;
    // returns 0 on success
    using stream_open_callback = std::function<uint64_t(Stream&)>;
    using stream_unblocked_callback = std::function<bool(Stream&)>;

    using stream_buffer = std::deque<std::pair<std::span<const std::byte>, std::shared_ptr<void>>>;

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message);
    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val);

    namespace opt
    {
        // Passing `opt::stream_notify` to the stream constructor makes the stream send an empty
        // stream frame if there is no initial data, to notify the other end that the stream has
        // opened.  Without this the remote only learns about the stream when the first data arrives
        // through that stream.  If you intend the stream to be fully bidirection before the
        // initiator sends anything, you want this option.
        struct stream_notify_t
        {};
        constexpr stream_notify_t stream_notify{};

        // opt::stream_fin allows passing a callback that will be called when the remote has
        // send a FIN bit (which indicates that it will send no more data).  This callback will be
        // called after all stream data has been processed.
        struct stream_fin_callback
        {
            std::function<void(Stream&)> cb;
        };
    }  // namespace opt

    class Stream : public IOChannel, public std::enable_shared_from_this<Stream>
    {
        friend class TestHelper;
        friend class Connection;
        friend class Network;
        friend class Loop;

      protected:
        template <typename... Opts>
        Stream(Connection& conn, Endpoint& ep, Opts&&... opts) : Stream{conn, ep, base_ctor{}}
        {
            (handle_opt(std::forward<Opts>(opts)), ...);
            set_default_callbacks();
        }

        struct base_ctor
        {};
        // Internal base delegating constructor, used internally and usable by subclasses: this does
        // *not* assign default data and close callbacks, and should be accompanied by a call to
        // `set_default_callbacks()` if they are wanted.
        Stream(Connection& conn, Endpoint& ep, base_ctor);

        void handle_opt(stream_data_callback data_cb);
        void handle_opt(stream_close_callback close_cb);
        void handle_opt(opt::stream_notify_t);
        void handle_opt(opt::stream_fin_callback fin_cb);

        void set_default_callbacks();

      public:
        ~Stream() override;

        bool is_stream() const override { return true; }
        // Returns the stream ID of this stream, or -1 if an ID has not been assigned yet (i.e. for
        // a pending stream).
        int64_t stream_id() const { return _stream_id; }

        const ConnectionID reference_id;

        /**
         * Enables unsent buffer "watermark" threshold callbacks that allow an application to be
         * notified when too much data has been queued on a stream that can't be sent yet (i.e.
         * because of connection congestion).  This allows an application to take action as a result
         * of stream data building up too fast and take other action when the condition resolves
         * itself.
         *
         * In order to make use of this, the application provides "alarm" and "clear" watermark buffer
         * sizes (in bytes) and two callbacks to be invoked when the watermarks are reached.
         *
         * When the stream has at least `alarm` bytes unsent, it triggers the watermark alarm
         * by calling `on_alarm(stream)` to notify the application of the alarm.  Once triggered,
         * it remains in alarm watermark state until the unsent stream data falls to (or below)
         * `clear` bytes unsent, at which point it calls the `on_clear(stream)` to signal that the
         * alarm is resolved.
         *
         * An alternative way to look at the clear/alarm values is that unsent byte levels >=
         * `alarm` are sufficient to trigger a watermark alarm, and levels > `clear` are sufficient
         * to sustain (but not trigger, unless also >= `alarm`) a high water mark alarm.
         *
         * The clear value must be strictly less than the alarm value; for an alarm with 1-byte
         * sensitivity, you can set clear = alarm - 1.  A clear value of 0 will not unsound the
         * alarm until *all* unsent bytes on the stream have been written into QUIC packets that are
         * on their way to the remote.
         *
         * The two callbacks can be nullptr to ignore them, in which case watermark status will
         * still be tracked (and can be queried via `watermark_status()`) but the callback won't be
         * invoked.
         *
         * Calling this when watermarking is already enabled replaces the existing watermark levels
         * and callbacks, but does *not* reset the current watermark state.  If watermarking is
         * currently disabled then the state is initialized to cleared (non-alarm) state.  This call
         * will immediately (i.e. during the enable_watermarks() call itself) invoke the alarm or
         * clear callback if the new values warrant a transition from the watermark state before the
         * call.
         *
         * Note that the watermark level is checked immediately after any data on the stream is
         * sent, and immediately after any new data is queued, and so setting a too low alarm value
         * could result in lots of false positives triggering when new data is queued, even if that
         * data might be immediately sendable on the connection.  Typically you want the `alarm`
         * value to be higher than the amount you would typically send all at once.
         */
        void enable_watermarks(
                size_t alarm, std::function<void(Stream&)> on_alarm, size_t clear, std::function<void(Stream&)> on_clear);

        // Clears any currently set watermarks on this stream object
        void disable_watermarks();

        // Returns the current watermark status: true if watermarks are enabled and currently in the
        // alarm watermark state; false if enabled and in the no-alarm state; nullopt if watermarks
        // are disabled.
        std::optional<bool> watermark_status() const;

        /**
         * Calling `pause()` stops extending the max stream data offset that gets returned to the
         * remote side of a connection.  By not increasing this offset, the
         * maximum that the remote is allowed to send to us stops increasing which can then block
         * the sender from sending any more once the current maximum stream buffer has been sent.
         * This in particular is useful with watermarking on the other end: a pause in the stream in
         * client A causes the other side of the stream in client B to back up, trigger B's
         * watermark and thus propagating whatever is producing data to stop it from sending more
         * data until things resolve.
         *
         * Call `resume()` to unblock the stream again.
         */
        void pause();
        bool is_paused() const;

        /**
         * Counterpart to pause(): when this is called the stream is resumed and any increase to the
         * stream data offset that was suppressed by the pause() call are applied to the stream
         * allowing data to flow again.
         */
        void resume();

        // Returns true if the stream is writeable, i.e. not closing, shutdown and FIN not sent or
        // scheduled.
        bool writable() const;

        // Returns true if the stream is potentially readable, i.e. not closed and the other side
        // has not sent a FIN yet.  A false return value means no more data will arrive on this
        // stream.
        bool readable() const;

        // Returns true if the stream is ready, that is, has an assigned stream ID and can send data
        // to the other side.  Note that, when a connection is established using 0-RTT, new streams
        // will be instantly ready (up to the server's stream limit as contained in the stored 0-RTT
        // data), but if 0-RTT fails, they will temporarily become unready again until the new, full
        // 1-RTT connection re-admits them as new streams.  Typically this is momentary, but it
        // could be prolonged if the server changed transport parameters to reduce the number of
        // available streams.
        bool is_ready() const;

        // Queues a FIN bit to be sent on the stream, and stop accepting any new stream data (i.e.
        // calling send() after this has been called on a stream simply drops the data).  If there
        // is currently queued data then the FIN bit is sent with the final stream data; if there is
        // no queued data then this causes an empty stream frame with a FIN bit to be sent.
        void send_fin();

        void close(uint64_t app_err_code = 0);

        // Replaces the existing stream data callback (if any) with the given one.
        void set_data_callback(stream_data_callback cb);
        // Replaces the existing stream close callback (if any) with the given one.
        void set_close_callback(stream_close_callback cb);
        // Replaces the existing stream FIN callback (if any) with the given one.
        void set_fin_callback(std::function<void(Stream&)> cb);

      protected:
        virtual void receive(std::span<const std::byte> data)
        {
            if (_data_callback)
                _data_callback(*this, data);
        }

        virtual void closed(uint64_t app_code);

        // Called immediately after set_ready so that a subclass can do thing as soon as the stream
        // becomes ready. The default does nothing.
        //
        // Note that when using 0-RTT, this will be fired *twice* if 0-RTT is attempted but fails:
        // once immediately upon stream construction (if the cached 0-RTT transport data allows the
        // stream to be opened), but then the 0-RTT failure will momentarily "un-ready" it
        // (`on_unready()` is called) if 0-RTT is rejected.  Typically it will then become ready
        // again almost immediately as the connection reopens as many 0-RTT streams as it can, but
        // note that this might not possible (for instance, if the server max streams values has
        // been reduced).
        virtual void on_ready() {}

        // Called when 0-RTT is rejected and the stream is returned to pending status, which may
        // only be momentary.  See above.
        virtual void on_unready() {}

        // Called when a stream FIN is received from the other end, indicating that the other end
        // will send no more data.  Calls the fin_callback, if set.  If overriding, be sure to call
        // the base class method to properly set the _received_fin bit.
        virtual void on_fin();

        /// Called periodically to check if anything needs to be timed out.  The default does
        /// nothing, but subclasses can override to not do nothing if it's not the case that nothing
        /// ain't not good enough isn't false.
        virtual void check_timeouts() {}

        void send_impl(std::span<const std::byte> data, std::shared_ptr<void> keep_alive) override;

        stream_buffer user_buffers;

        bool has_unsent_impl() const override { return not is_empty_impl(); }
        bool is_closing_impl() const override { return _is_closing; }
        bool is_empty_impl() const override { return user_buffers.empty(); }
        size_t unsent_impl() const override;

        /// Called on ACKs to confirm that the first `bytes` of queued stream data has been acked by
        /// the other side.  The base Stream class uses this to tracking and free pending buffers
        /// once no longer needed.  If overriding, be sure to call the base class method!
        virtual void wrote(size_t bytes);

      private:
        // Called if 0-RTT early data was rejected; marks all sent data as unsent
        void revert_stream();

        // Returns ngtcp2 vector of user buffer pointers of unsent data.  Returned buffers cover at
        // least `bytes` of unsent data (if available).  The second value of the pair will be true
        // if there is more stream data queued beyond the returned user buffers, false if the user
        // buffers cover to the end of currently queued data.  (If there is no `more` *and*
        // _send_fin is set then we know it is time to give the FIN flag to ngtcp2).  This is
        // primary used by connection.cpp to obtain the next chunk of data from this stream.
        std::pair<std::vector<ngtcp2_vec>, bool> pending(size_t bytes);

        size_t _unsent_size{0};
        size_t _unacked_size{0};
        size_t _current_buffer_index{0};
        size_t _current_buffer_offset{0};
        size_t _total_buffer_size{0};
        bool _is_closing{false};
        bool _send_fin{false};
        bool _sent_fin{false};
        bool _received_fin{false};
        bool _ready{false};
        bool _paused{false};
        bool _notify{false};
        bool _had_notify{false};
        int64_t _stream_id{-1};

        size_t _paused_offset{0};

        stream_data_callback _data_callback;
        stream_close_callback _close_callback;
        std::function<void(Stream&)> _fin_callback;

        std::optional<std::pair<size_t, size_t>> _watermarking;  // {alarm threshold, all-clear threshold}
        bool _watermark_alarm{false};
        std::function<void(Stream&)> _watermark_on_alarm;
        std::function<void(Stream&)> _watermark_on_clear;

        void append_buffer(std::span<const std::byte> buffer, std::shared_ptr<void> keep_alive);

        void check_watermark();
        void acknowledge(size_t bytes);

        size_t size() const { return _total_buffer_size; }

        size_t unacked() const { return _unacked_size; }

        // Implementations classes for send_chunks()

        // chunk_sender: When sending chunks we construct *one* of these, then share its ownership
        // across all the chunks in flight.  When each individual chunk gets destroyed, it called
        // back into this to queue the next chunk, which this class then sends into the stream.
        //
        // Container -- can be a value or a pointer, but not a reference.
        template <typename Container>
        struct chunk_sender : std::enable_shared_from_this<chunk_sender<Container>>
        {
            static_assert(!std::is_reference_v<Container>, "chunk_sender requires a value or pointer, not a reference");

            static constexpr bool is_pointer = std::is_pointer_v<Container> ||
                                               is_instantiation<std::unique_ptr, Container> ||
                                               is_instantiation<std::shared_ptr, Container>;

            using chunk_callback_t = std::function<Container(const Stream&)>;
            using done_callback_t = std::function<void(Stream&)>;

            template <typename... Args>
            static void make(int initial_queue, Args&&... args)
            {
                std::shared_ptr<chunk_sender<Container>> cs{new chunk_sender<Container>(std::forward<Args>(args)...)};
                for (int i = 0; i < initial_queue; i++)
                    cs->queue_next_chunk();
            }

          private:
            // This is instantiated for each chunk, contains the chunk data itself, and is what we
            // put into the keep_alive; during destruction, we queue the next chunk.
            struct single_chunk
            {
              private:
                std::shared_ptr<chunk_sender> _chunks;
                Container _data;

              public:
                single_chunk(chunk_sender& cs, Container&& d) : _chunks{cs.shared_from_this()}, _data{std::move(d)} {}
                ~single_chunk() { _chunks->queue_next_chunk(); }

                std::span<const std::byte> view() const
                {
                    if constexpr (is_pointer)
                    {
                        static_assert(sizeof(*_data->data()) == 1, "chunk_sender requires bytes data");
                        return {reinterpret_cast<const std::byte*>(_data->data()), _data->size()};
                    }
                    else
                    {
                        static_assert(sizeof(*_data.data()) == 1, "chunk_sender requires bytes data");
                        return {reinterpret_cast<const std::byte*>(_data.data()), _data.size()};
                    }
                }
            };

            chunk_sender(Stream& s, chunk_callback_t next, done_callback_t done) :
                    str{s}, next_chunk{std::move(next)}, done{std::move(done)}
            {
                assert(next_chunk);
            }

            Stream& str;
            chunk_callback_t next_chunk;
            done_callback_t done;

          public:
            void queue_next_chunk()
            {
                if (!next_chunk)
                    // We already finished (i.e. via a previous chunk destructor)
                    return;

                auto data = next_chunk(const_cast<const Stream&>(str));
                bool no_data = false;
                if constexpr (is_pointer)
                    no_data = !data || data->size() == 0;
                else
                    no_data = data.size() == 0;

                if (no_data)
                {
#ifndef NDEBUG
                    _chunk_sender_trace(__FILE__, __LINE__, "send_chunks finished");
#endif
                    // We're finishing
                    next_chunk = nullptr;
                    if (done)
                        done(str);
                    return;
                }

                auto next = std::make_shared<single_chunk>(*this, std::move(data));
                auto bsv = next->view();
#ifndef NDEBUG
                _chunk_sender_trace(__FILE__, __LINE__, "got chunk to send of size ", bsv.size());
#endif
                str.send(bsv, std::move(next));
            }
        };

      public:
        /// Sends data in chunks: `next_chunk` is some callable (e.g. lambda) that will be called
        /// with a const reference to the stream instance as needed to obtain the next chunk of data
        /// until it returns an empty container, at which point `done(stream)` will be called.
        /// Chunks are called when a previous chunk has been completely send and acknolwedged by the
        /// other end of the stream.
        ///
        /// next_chunk() can return any contiguous container with `.data()` and `.size()` member
        /// functions as long as `.data()` returns a pointer to a single-byte type (e.g.
        /// std::string, std::vector of bytes, etc. are acceptable), or a
        /// pointer/unique_ptr/shared_ptr to such a container.  If returned by value the container
        /// or smart pointer will be moved and kept until no longer needed; if returned by raw
        /// pointer then it must remain valid until the stream chunk is complete.  When returning a
        /// pointer either an empty container or a nullptr can be returned to signal the end of the
        /// data.
        ///
        /// Note that done() is called once all chunks are queued, *not* once all chunks are
        /// acknoledged; this allows you to use the `done` callback to know when it is safe to
        /// append data to followed the chunked data.
        ///
        /// simultaneous controls how many initial chunks to queue up (and thus also how many chunks
        /// will be in-flight at a given time), and must be at least 1.  You can rely on no more
        /// than simultaneous being active at a time (and so, for example, can safely return
        /// pointers to a circular buffer of `simultaneous` Containers).
        template <typename NextChunk>
        void send_chunks(NextChunk next_chunk, std::function<void(Stream&)> done = nullptr, int simultaneous = 2)
        {
            if (simultaneous < 1)
                throw std::logic_error{"Stream::send_chunks simultaneous must be >= 1"};

            using T = decltype(next_chunk(const_cast<const Stream&>(*this)));
            chunk_sender<T>::make(simultaneous, *this, std::move(next_chunk), std::move(done));
        }

        void set_ready(bool ready = true);
    };
}  // namespace oxen::quic
