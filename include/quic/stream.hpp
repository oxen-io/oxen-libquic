#pragma once

extern "C"
{
#include <ngtcp2/ngtcp2.h>
}

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <queue>
#include <variant>
#include <vector>

#include "datagram.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Stream;
    class Endpoint;
    class Connection;
    struct ConnectionID;

    // Stream callbacks
    using stream_data_callback = std::function<void(Stream&, bstring_view)>;
    using stream_close_callback = std::function<void(Stream&, uint64_t error_code)>;
    // returns 0 on success
    using stream_open_callback = std::function<uint64_t(Stream&)>;
    using stream_unblocked_callback = std::function<bool(Stream&)>;

    class Stream : public IOChannel, public std::enable_shared_from_this<Stream>
    {
        friend class Connection;

      public:
        Stream(Connection& conn,
               Endpoint& ep,
               stream_data_callback data_cb = nullptr,
               stream_close_callback close_cb = nullptr,
               int64_t stream_id = -1);
        Stream(Connection& conn, Endpoint& ep, int64_t stream_id) : Stream{conn, ep, nullptr, nullptr, stream_id} {}
        ~Stream();

        bool available() const { return !(_is_closing || is_shutdown || _sent_fin); }
        bool is_stream() const override { return true; }

        int64_t stream_id() const override { return _stream_id; }
        const ConnectionID& conn_id() const;

        bool has_unsent() const override { return not is_empty(); }

        bool is_closing() const override { return _is_closing; }
        bool sent_fin() const override { return _sent_fin; }
        void set_fin(bool v) override { _sent_fin = v; }

        std::shared_ptr<Stream> get_stream() override;

        void close(uint64_t error_code = 0);

        void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        template <
                typename CharType,
                std::enable_if_t<sizeof(CharType) == 1 && !std::is_same_v<CharType, std::byte>, int> = 0>
        void send(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive = nullptr)
        {
            send(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        template <typename CharType>
        void send(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            send(view, std::move(keep_alive));
        }

        template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
        void send(std::vector<Char>&& buf)
        {
            send(std::basic_string_view<Char>{buf.data(), buf.size()}, std::make_shared<std::vector<Char>>(std::move(buf)));
        }

        void set_stream_data_cb(stream_data_callback cb) { data_callback = std::move(cb); }

        void set_stream_close_cb(stream_close_callback cb) { close_callback = std::move(cb); }

        stream_data_callback data_callback;
        stream_close_callback close_callback;

      private:
        stream_buffer user_buffers;

        std::vector<ngtcp2_vec> pending() override;

        size_t unacked_size{0};
        bool _is_closing{false};
        bool is_shutdown{false};
        bool _sent_fin{false};
        bool ready{false};
        int64_t _stream_id;

        Connection& get_conn();

        bool is_empty() const override { return user_buffers.empty(); }

        void wrote(size_t bytes) override;

        void append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive);

        void acknowledge(size_t bytes);

        inline size_t size() const
        {
            size_t sum{0};
            if (user_buffers.empty())
                return sum;
            for (const auto& [data, store] : user_buffers)
                sum += data.size();
            return sum;
        }

        inline size_t unacked() const { return unacked_size; }

        inline size_t unsent() const override
        {
            log::trace(log_cat, "size={}, unacked={}", size(), unacked());
            return size() - unacked();
        }

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
                    log::trace(log_cat, "send_chunks finished");
                    // We're finishing
                    next_chunk = nullptr;
                    if (done)
                        done(str);
                    return;
                }

                auto next = std::make_shared<single_chunk>(*this, std::move(data));
                auto bsv = next->view();
                log::trace(log_cat, "got chunk to send of size {}", bsv.size());
                str.send(bsv, std::move(next));
            }
        };

        prepared_datagram pending_datagram(bool) override
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            throw std::runtime_error{"Stream objects should not be queried for pending datagrams!"};
        }

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

        inline void set_ready()
        {
            log::trace(log_cat, "Setting stream ready");
            ready = true;
        }
        inline void set_not_ready()
        {
            log::trace(log_cat, "Setting stream not ready");
            ready = false;
        }
    };
}  // namespace oxen::quic
