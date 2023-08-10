#pragma once

#include "messages.hpp"
#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Connection;
    class Endpoint;
    class Stream;
    class connection_interface;
    struct ConnectionID;

    struct dgram_interface
    {
        dgram_interface(Connection& c);
        connection_interface& ci;

        const ConnectionID& conn_id() const;

        std::shared_ptr<connection_interface> get_conn_interface();

        template <
                typename CharType,
                std::enable_if_t<sizeof(CharType) == 1 && !std::is_same_v<CharType, std::byte>, int> = 0>
        void reply(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive = nullptr)
        {
            reply(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
        void send_datagram(std::vector<Char>&& buf)
        {
            reply(std::basic_string_view<Char>{buf.data(), buf.size()}, std::make_shared<std::vector<Char>>(std::move(buf)));
        }

        template <typename CharType>
        void reply(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            reply(view, std::move(keep_alive));
        }

        void reply(bstring_view data, std::shared_ptr<void> keep_alive = nullptr);
    };

    // IO callbacks
    using dgram_data_callback = std::function<void(dgram_interface&, bstring)>;

    using dgram_buffer = std::deque<std::pair<uint16_t, std::pair<bstring_view, std::shared_ptr<void>>>>;

    class IOChannel
    {
      public:
        IOChannel(Connection& c, Endpoint& e);

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
        virtual void send(bstring_view, std::shared_ptr<void> keep_alive = nullptr) = 0;
        virtual std::vector<ngtcp2_vec> pending() = 0;
        virtual prepared_datagram pending_datagram(bool) = 0;
        virtual int64_t stream_id() const = 0;
        virtual bool is_closing() const = 0;
        virtual bool sent_fin() const = 0;
        virtual void set_fin(bool) = 0;
        virtual size_t unsent() const = 0;
        virtual void wrote(size_t) = 0;
        virtual bool has_unsent() const = 0;
    };

    class CustomChannelBase
    {
        virtual void handle_opt();

        virtual void initialize();
        
    };
    
    class UserChannelBase : public CustomChannelBase, public IOChannel
    {
      public:
        UserChannelBase(Connection& c, Endpoint& e) : IOChannel{c, e} {}
    };

    template <
            typename T, 
            typename... Opt,
            std::enable_if_t<std::is_base_of_v<UserChannelBase, T>, int> = 0>
    static std::shared_ptr<T> make_bridge(Endpoint& e, Connection& c, Opt&&... opts)
    {
        auto sp = std::shared_ptr<T>(new T{e, c});
        ((void)sp->handle_opt(std::forward<Opt>(opts)), ...);
        sp->initialize();
    }

    class DatagramIO : public IOChannel
    {
      public:
        DatagramIO(Connection& c, Endpoint& e, dgram_data_callback data_cb = nullptr);
        dgram_data_callback dgram_data_cb;

        /// Datagram Numbering:
        /// Each datagram ID is comprised of a 16 bit quantity consisting of a 14 bit counter, and
        /// two bits indicating whether the packet is split or not, and, if split, which portion the
        /// associated split packet datagram represents.
        ///
        /// For example,
        ///
        ///     ID: 0bxxxx'xxxx'xxxx'xxzz
        ///                            ^^
        ///               split/nosplit|first or second packet
        ///
        /// Example - unsplit packets:
        ///     Packet Number   |   Packet ID
        ///         1           |       4           In the unsplit packet scheme, the dgram ID of each
        ///         2           |       8           datagram satisfies the rule:
        ///         3           |       12                          (ID % 4) == 0
        ///         4           |       16          As a result, if a dgram ID is received that is a perfect
        ///         5           |       20          multiple of 4, that packet is NOT split
        ///
        /// Example - split packets:
        ///     Packet Number   |   Packet ID
        ///         1                   6           In the split-packet scheme, the dgram ID of the first
        ///         2                   7           of two datagrams satisfies the rule:
        ///         3                   10                          (ID % 4) == 2
        ///         4                   11          The second of the two datagrams satisfies the rule:
        ///         5                   14                          (ID % 4) == 3
        ///         6                   15          As a result, a packet-splitting endpoint should never send
        ///                                         or receive a datagram whose ID is a perfect multiple of 4
        ///
        /// Example - sending split and whole packets:
        ///     Packet Number   |   Packet ID
        ///         1                   6           When sending both split and unsplit packets, the above
        ///         2                   7           numbering is still followed. In the example to the left, the
        ///         3*                  8           unsplit packets are marked with an asterisk(*). An unsplit
        ///         4                   14          packet takes the entire 4-ID block, and the next split packet
        ///         5                   15          begins from the next 4-ID. This way, a receiving endpoint will
        ///         6*                  16          have no confusion on datagram reception when matching split packets
        ///         7                   22          sent intermixed with unsplit packets.
        ///         8                   23
        ///
        uint16_t _next_dgram_counter{0};  // The id *before* shifting the split/side bits

        const int rbufsize;

        /// Holds received datagrams in a rotating "tetris" ring-buffer arrangement of split, unmatched packets.
        /// When a datagram with ID N is recieved, we store it as:
        ///
        ///         tetris_buffer[i][j]
        /// where,
        ///         i = (N % 4096) / 1024
        ///         j = N % 1024
        ///
        /// When it comes to clearing the buffers, the last cleared row is stored in Connection::_last_cleared.
        /// The next row to clear is found as:
        ///
        ///         to_clear = (i + 2) % 4;
        ///         if (to_clear == (last_cleared+1)%4)
        ///         {
        ///             clear(to_clear)
        ///             last_cleared = to_clear
        ///         }
        ///
        /// In full, given 'last_cleared' and a target index 'to_clear', we clear 'to_clear' when 'i' is:
        ///     last_cleared  |  to_clear  |  i
        /// (init) -1               1         3
        ///         0               2         0
        ///         1               3         1
        ///         2               0         2
        ///         3               1         3
        ///
        rotating_buffer recv_buffer;
        // dgram_buffer send_buffer;
        buffer_que send_buffer;

        bool is_empty() const override { return send_buffer.empty(); }

        void send(bstring_view data, std::shared_ptr<void> keep_alive = nullptr) override;

        prepared_datagram pending_datagram(bool r) override;

        bool is_stream() const override { return false; }

        std::optional<bstring> to_buffer(bstring_view data, uint16_t dgid);

        int datagrams_stored() const { return recv_buffer.datagrams_stored(); };

      private:
        const bool _packet_splitting{false};

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
            if (send_buffer.empty())
                return sum;
            for (const auto& entry : send_buffer.buf)
                sum += entry.size();
            return sum;
        };
        bool has_unsent() const override { return not is_empty(); }
        void wrote(size_t) override { log::debug(log_cat, "{} called", __PRETTY_FUNCTION__); };
        std::vector<ngtcp2_vec> pending() override
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            return {};
        };
    };

}  // namespace oxen::quic
