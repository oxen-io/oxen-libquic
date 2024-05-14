#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <queue>
#include <variant>
#include <vector>

#include "connection_ids.hpp"
#include "error.hpp"
#include "iochannel.hpp"
#include "opt.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Stream;
    class Endpoint;
    class Connection;
    struct quic_cid;

    // Stream callbacks
    using stream_data_callback = std::function<void(Stream&, bstring_view)>;
    using stream_close_callback = std::function<void(Stream&, uint64_t error_code)>;
    using stream_constructor_callback =
            std::function<std::shared_ptr<Stream>(Connection&, Endpoint&, std::optional<int64_t>)>;
    // returns 0 on success
    using stream_open_callback = std::function<uint64_t(Stream&)>;
    using stream_unblocked_callback = std::function<bool(Stream&)>;

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message);
    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val);

    class Stream : public IOChannel, public std::enable_shared_from_this<Stream>
    {
        friend class TestHelper;
        friend class Connection;
        friend class Network;
        friend class Loop;

      protected:
        Stream(Connection& conn,
               Endpoint& ep,
               stream_data_callback data_cb = nullptr,
               stream_close_callback close_cb = nullptr);

      public:
        ~Stream() override;

        bool is_stream() const override { return true; }
        int64_t stream_id() const override { return _stream_id; }

        const ConnectionID reference_id;

        /** Buffer Watermarking:
            - Applications can call `::set_watermark(...)` to implement logic to be executed at states dictated by the number
                of bytes currently unsent.
            - Application must pass `low` and `high` watermark amounts; an execute-on-low callback can be passed with or
                without an execute-on-high callback (and vice versa)
                - The execute-on-low callback will not be executed until the buffer state rises above the `high` value; it
                    will not be executed again until the buffer state rises once more above the `high` value
                - The execute-on-high callback will not be executed until the buffer state drops below the `low` value; it
                    will not be executed again until the buffer state drops once more below the `low` value
            - Callbacks can be passed with an optional boolean in their opt:: wrapper, indicating "clear after execution";
                this will ensure the callback is only executed ONCE before being cleared. The default behavior is repeated
                callback execution
            - Invoking this function repeatedly will overwrite any currently set thresholds and callbacks
        */
        void set_watermark(
                size_t low, size_t high, std::optional<opt::watermark> low_hook, std::optional<opt::watermark> high_hook);

        // Clears any currently set watermarks on this stream object
        void clear_watermarks();

        // Do not call this function from within a watermark callback!
        bool has_watermarks() const;

        /** Stream Pause:
            - Applications can call `::pause()` to stop extending the max stream data offset. This has the effect of limiting
                the inflow by signalling to the sender that they should pause
            - This is reverted by invoking `::resume()`
        */
        void pause();

        void resume();

        bool is_paused() const;

        /** Remote Stream Reset:
            - Applications can call `::set_remote_reset_hooks(...)` to emplace logic to be executed when the remote stream
                shuts down reading and/or writing
            - This only happens once per lifetime of the stream; as a result, do NOT set more hooks while inside the body of
                the hooks themselves!
        */
        void set_remote_reset_hooks(opt::remote_stream_reset hooks);

        void clear_remote_reset_hooks();

        bool has_remote_reset_hooks() const;

        void stop_reading();

        void stop_writing();

        void stop_sending(uint64_t code = STREAM_REMOTE_READ_SHUTDOWN);

        void reset_stream(uint64_t code = STREAM_REMOTE_WRITE_SHUTDOWN);

        bool is_reading() const;

        bool is_writing() const;

        // These public methods are synchronized so that they can be safely called from outside the
        // libquic main loop thread.
        bool available() const;
        bool is_ready() const;

        std::shared_ptr<Stream> get_stream() override;

        std::shared_ptr<connection_interface> get_conn_interface();

        void close(uint64_t app_err_code = 0);

        void set_stream_data_cb(stream_data_callback cb) { data_callback = std::move(cb); }
        void set_stream_close_cb(stream_close_callback cb) { close_callback = std::move(cb); }

        stream_data_callback data_callback;
        stream_close_callback close_callback;

      protected:
        virtual void receive(bstring_view data)
        {
            if (data_callback)
                data_callback(*this, data);
        }

        virtual void closed(uint64_t app_code);

        // Called immediately after set_ready so that a subclass can do thing as soon as the stream
        // becomes ready. The default does nothing.
        virtual void on_ready() {}

        /// Called periodically to check if anything needs to be timed out.  The default does
        /// nothing, but subclasses can override to not do nothing if it's not the case that nothing
        /// ain't not good enough isn't false.
        virtual void check_timeouts() {}

        void send_impl(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        stream_buffer user_buffers;

        bool sent_fin() const override { return _sent_fin; }
        void set_fin(bool v) override { _sent_fin = v; }

        bool has_unsent_impl() const override { return not is_empty_impl(); }
        bool is_closing_impl() const override { return _is_closing; }
        bool is_empty_impl() const override { return user_buffers.empty(); }
        size_t unsent_impl() const override;

      private:
        std::vector<ngtcp2_vec> pending() override;

        size_t _unacked_size{0};
        bool _is_closing{false};
        bool _is_shutdown{false};
        bool _sent_fin{false};
        bool _ready{false};
        bool _paused{false};
        int64_t _stream_id;

        std::atomic<size_t> _paused_offset{0};

        bool _is_watermarked{false};

        size_t _high_mark{0};
        size_t _low_mark{0};

        bool _high_primed{false};
        bool _low_primed{true};

        opt::watermark _high_water;
        opt::watermark _low_water;

        opt::remote_stream_reset _remote_reset;

        bool _in_reset{false};

        bool _is_reading{true};
        bool _is_writing{true};
        uint64_t _deferred_ec{0};

        void wrote(size_t bytes) override;

        void append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive);

        void acknowledge(size_t bytes);

        size_t size() const
        {
            size_t sum{0};
            if (user_buffers.empty())
                return sum;
            for (const auto& [data, store] : user_buffers)
                sum += data.size();
            return sum;
        }

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

                bstring_view view() const
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

        prepared_datagram pending_datagram(bool) override;

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

        void set_ready();
    };
}  // namespace oxen::quic
