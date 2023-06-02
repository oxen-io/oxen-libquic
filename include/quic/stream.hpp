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
#include <uvw.hpp>
#include <variant>
#include <vector>

#include "utils.hpp"

namespace oxen::quic
{
    class Connection;

    class Stream : public std::enable_shared_from_this<Stream>
    {
        friend class Connection;

      public:
        Stream(Connection& conn,
               stream_data_callback_t data_cb = nullptr,
               stream_close_callback_t close_cb = nullptr,
               int64_t stream_id = -1);
        Stream(Connection& conn, int64_t stream_id);
        ~Stream();

        stream_data_callback_t data_callback;
        stream_close_callback_t close_callback;
        Connection& conn;

        int64_t stream_id;
        std::shared_ptr<uvw::UDPHandle> udp_handle;
        std::vector<uint8_t> data;
        size_t datalen;
        size_t nwrite;

        std::deque<std::pair<bstring_view, std::shared_ptr<void>>> user_buffers;

        Connection& get_conn();

        void close(uint64_t error_code = 0);

        void io_ready();

        void available_ready();

        void wrote(size_t bytes);

        void when_available(unblocked_callback_t unblocked_cb);

        void append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive);

        void acknowledge(size_t bytes);

        inline bool available() const { return !(is_closing || is_shutdown || sent_fin); }

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

        inline size_t unsent() const
        {
            log::trace(log_cat, "size={}, unacked={}", size(), unacked());
            return size() - unacked();
        }

        // Retrieve stashed data with static cast to desired type
        template <typename T>
        std::shared_ptr<T> get_user_data() const
        {
            return std::static_pointer_cast<T>(
                    std::holds_alternative<std::shared_ptr<void>>(user_data)
                            ? std::get<std::shared_ptr<void>>(user_data)
                            : std::get<std::weak_ptr<void>>(user_data).lock());
        }

        void set_user_data(std::shared_ptr<void> data);

        void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr);

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

      private:
        // Implementations classes for send_chunks()

        // chunk_sender: When sending chunks we construct *one* of these, then share its ownership
        // across all the chunks in flight.  When each individual chunk gets destroyed, it called
        // back into this to queue the next chunk, which this class then sends into the stream.
        template <typename Container>
        struct chunk_sender : std::enable_shared_from_this<chunk_sender<Container>>
        {
            using chunk_callback_t = std::function<Container()>;
            using done_callback_t = std::function<void()>;

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
                std::shared_ptr<chunk_sender> chunks;
                Container data;

                single_chunk(chunk_sender& cs, Container&& d) : chunks{cs.shared_from_this()}, data{std::move(d)} {}
                ~single_chunk() { chunks->queue_next_chunk(); }
            };

            chunk_sender(Stream& s, chunk_callback_t next, done_callback_t done) :
                    str{s}, next_chunk{std::move(next)}, done{std::move(done)}
            {
                assert(next_chunk);
            }

            Stream& str;
            std::shared_ptr<Container> data;
            chunk_callback_t next_chunk;
            done_callback_t done;

          public:
            void queue_next_chunk()
            {
                if (!next_chunk)
                    // We already finished (i.e. via a previous chunk destructor)
                    return;

                auto data = next_chunk();
                if (data.empty())
                {
                    log::trace(log_cat, "send_chunks finished");
                    // We're finishing
                    next_chunk = nullptr;
                    if (done)
                        done();
                    return;
                }

                auto next = std::make_shared<single_chunk>(*this, std::move(data));
                log::trace(log_cat, "got chunk to send of size {}", next->data.size());
                bstring_view bsv{reinterpret_cast<const std::byte*>(next->data.data()), next->data.size()};
                str.send(bsv, std::move(next));
            }
        };

      public:
        /// Sends data in chunks: `next_chunk()` will be called to obtain the next chunk of data
        /// until it returns an empty container, at which point `done()` will be called.  Chunks are
        /// called when a previous chunk has been completely send and acknolwedged by the other end
        /// of the stream.
        ///
        /// Note that done() is called once all chunks are queued, *not* once all chunks are
        /// acknoledged; this allows you to use the `done` callback to know when it is safe to
        /// append data to followed the chunked data.
        ///
        /// simultaneous controls how many initial chunks to queue up (and thus also how many chunks
        /// will be in-flight at a given time), and must be at least 1.
        template <typename T = std::string>
        void send_chunks(std::function<T()> next_chunk, std::function<void()> done = nullptr, int simultaneous = 2)
        {
            assert(next_chunk);
            if (simultaneous < 1)
                throw std::logic_error{"Stream::send_chunks simultaneous must be >= 1"};

            chunk_sender<T>::make(simultaneous, *this, std::move(next_chunk), std::move(done));
        }

        inline void set_ready() { ready = true; };
        inline void set_not_ready() { ready = false; };

      private:
        // Callback(s) to invoke once we have the requested amount of space available in the buffer.
        std::queue<unblocked_callback_t> unblocked_callbacks;

        void handle_unblocked();  // Processes the above if space is available

        std::vector<ngtcp2_vec> pending();

        // amount of unacked bytes
        size_t unacked_size{0};

        bool is_closing{false};
        bool is_shutdown{false};
        bool sent_fin{false};
        bool ready{false};

        // Async trigger for batch scheduling callbacks
        std::shared_ptr<uvw::AsyncHandle> avail_trigger;

        // TOTHINK: maybe should store a ptr to network or handler here?
        std::variant<std::shared_ptr<void>, std::weak_ptr<void>> user_data;
    };
}  // namespace oxen::quic
