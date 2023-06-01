#pragma once

#include <ngtcp2/ngtcp2.h>
#include <stddef.h>
#include <stdint.h>

#include <any>
#include <cassert>
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
    // using stream_data_callback_t = std::function<void(Stream&, bstring_view)>;
    // using stream_close_callback_t = std::function<void(Stream&, uint64_t error_code)>;
    // using unblocked_callback_t = std::function<bool(Stream&)>;

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

        std::deque<std::pair<bstring_view, std::any>> user_buffers;

        Connection& get_conn();

        void close(uint64_t error_code = 0);

        void io_ready();

        void available_ready();

        void wrote(size_t bytes);

        void when_available(unblocked_callback_t unblocked_cb);

        void append_buffer(bstring_view buffer, std::any keep_alive);

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

        void send(bstring_view data, std::any keep_alive);

        inline void send(bstring_view data) { send(data, std::move(data)); }

        template <
                typename CharType,
                std::enable_if_t<sizeof(CharType) == 1 && !std::is_same_v<CharType, std::byte>, int> = 0>
        void send(std::basic_string_view<CharType> data, std::any keep_alive)
        {
            send(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
        void send(std::vector<Char>&& buf)
        {
            send(std::basic_string_view<Char>{buf.data(), buf.size()}, std::move(buf));
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
