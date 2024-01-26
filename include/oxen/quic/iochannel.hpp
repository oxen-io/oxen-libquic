#pragma once
#include "messages.hpp"
#include "utils.hpp"

namespace oxen::quic
{

    class Connection;
    class Endpoint;
    class Stream;

    class IOChannel
    {
      protected:
        IOChannel(Connection& c, Endpoint& e) : conn{c}, endpoint{e}
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        }

      public:
        virtual ~IOChannel() { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };

        Connection& conn;
        Endpoint& endpoint;

        // no copy, no move. always hold in a shared pointer
        IOChannel(const IOChannel&) = delete;
        IOChannel& operator=(const IOChannel&) = delete;
        IOChannel(IOChannel&&) = delete;
        IOChannel& operator=(IOChannel&&) = delete;

        virtual bool is_stream() const = 0;
        virtual bool is_empty() const = 0;
        virtual std::shared_ptr<Stream> get_stream() = 0;
        virtual std::vector<ngtcp2_vec> pending() = 0;
        virtual prepared_datagram pending_datagram(bool) = 0;
        virtual int64_t stream_id() const = 0;
        virtual bool is_closing() const = 0;
        virtual bool sent_fin() const = 0;
        virtual void set_fin(bool) = 0;
        virtual size_t unsent() const = 0;
        virtual void wrote(size_t) = 0;
        virtual bool has_unsent() const = 0;

        template <typename CharType, std::enable_if_t<sizeof(CharType) == 1, int> = 0>
        void send(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive = nullptr)
        {
            send_impl(convert_sv<std::byte>(data), std::move(keep_alive));
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

      protected:
        // This is the (single) send implementation that implementing classes must provide; other
        // calls to send are converted into calls to this.
        virtual void send_impl(bstring_view, std::shared_ptr<void> keep_alive) = 0;
    };

}  // namespace oxen::quic
