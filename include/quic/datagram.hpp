#pragma once

#include "utils.hpp"

namespace oxen::quic
{
    class IOChannel;
    class Connection;
    class Endpoint;
    class Stream;

    // IO callbacks
    using dgram_data_callback = std::function<void(bstring_view)>;

    class IOChannel
    {
      public:
        IOChannel(Connection& c, Endpoint& e);

        virtual ~IOChannel() { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); };

        Connection& conn;
        Endpoint& endpoint;
        buffer_que user_buffers;

        // no copy, no move. always hold in a shared pointer
        IOChannel(const IOChannel&) = delete;
        IOChannel& operator=(const IOChannel&) = delete;
        IOChannel(IOChannel&&) = delete;
        IOChannel& operator=(IOChannel&&) = delete;

        virtual bool is_stream() = 0;
        virtual bool is_empty() const = 0;
        virtual std::shared_ptr<Stream> get_stream() = 0;
        virtual void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) = 0;
        virtual std::vector<ngtcp2_vec> pending() = 0;
        virtual void append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive) = 0;
        virtual int64_t stream_id() const = 0;
        virtual bool is_closing() const = 0;
        virtual bool sent_fin() const = 0;
        virtual void set_fin(bool v) = 0;
        virtual size_t unsent() const = 0;
        virtual void wrote(size_t n) = 0;
        virtual bool has_unsent() const { return (unsent() > 0); };
    };

    class DatagramIO : public IOChannel
    {
      public:
        DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb = nullptr);
        dgram_data_callback dgram_data_cb;

        bool is_empty() const override { return user_buffers.empty(); }

        void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;
        void append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive) override;
        std::vector<ngtcp2_vec> pending() override;

        bool is_stream() override { return false; }

      private:
        std::shared_ptr<Stream> get_stream() override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return nullptr;
        };
        int64_t stream_id() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return std::numeric_limits<int64_t>::min();
        };
        bool is_closing() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        bool sent_fin() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            return false;
        };
        void set_fin(bool) override { log::debug(log_cat, "{} called", __PRETTY_FUNCTION__); };
        size_t unsent() const override
        {
            log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
            size_t sum{0};
            if (user_buffers.empty())
                return sum;
            for (const auto& [data, store] : user_buffers)
                sum += data.size();
            return sum;
        };
        bool has_unsent() const override { return is_empty(); }
        void wrote(size_t) override { log::debug(log_cat, "{} called", __PRETTY_FUNCTION__); };
    };

}  // namespace oxen::quic
