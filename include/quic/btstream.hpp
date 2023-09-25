#include <oxenc/bt.h>

#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline auto bp_cat = oxen::log::Cat("bparser");

    using time_point = std::chrono::steady_clock::time_point;

    // timeout is used for sent requests awaiting responses
    inline constexpr std::chrono::seconds TIMEOUT{10};

    // request sizes
    inline constexpr long long MAX_REQ_LEN = 10_M;

    // Application error
    inline constexpr uint64_t BPARSER_EXCEPTION = (1ULL << 60) + 69;

    class BTRequestStream;

    struct message
    {
        friend class BTRequestStream;

      private:
        int64_t req_id;
        std::string data;
        std::string_view req_type;
        std::string_view endpoint;
        std::string_view req_body;
        std::weak_ptr<BTRequestStream> return_sender;
        bool timed_out{false};

      public:
        message(BTRequestStream& bp, std::string req, bool is_error = false);

        void respond(int64_t rid, std::string body, bool error = false);

        //  To be used to determine if the message was a result of an error as such:
        //
        //  void f(const message& m)
        //  {
        //      if (not m.timed_out)
        //      { // success logic }
        //      ... // is identical to:
        //      if (m)
        //      { // success logic }
        //  }
        operator bool() const { return not timed_out; }

        int64_t rid() const { return req_id; }
        std::string_view view() const { return {data}; }
    };

    struct sent_request
    {
        // parsed request data
        int64_t req_id;
        std::string data;
        BTRequestStream& return_sender;

        // total length of the request; is at the beginning of the request
        size_t total_len;

        std::chrono::steady_clock::time_point req_time;
        std::chrono::steady_clock::time_point timeout;

        bool is_empty() const { return data.empty() && total_len == 0; }

        explicit sent_request(BTRequestStream& bp, std::string_view d, int64_t rid);

        bool is_expired(std::chrono::steady_clock::time_point tp) const { return timeout < tp; }

        message to_message(bool timed_out = false) { return {return_sender, data, timed_out}; }

        std::string_view view() { return {data}; }
        std::string payload() && { return std::move(data); }
    };

    class BTRequestStream : public Stream
    {
      private:
        // outgoing requests awaiting response
        std::deque<std::shared_ptr<sent_request>> sent_reqs;

        std::string buf;
        std::string size_buf;

        size_t current_len{0};

        std::atomic<int64_t> next_rid{0};

        friend struct sent_request;
        std::function<void(message)> recv_callback;

      public:
        template <typename... Opt>
        explicit BTRequestStream(Connection& _c, Endpoint& _e, Opt&&... opts) : Stream{_c, _e}
        {
            ((void)handle_bp_opt(std::forward<Opt>(opts)), ...);
        }

        ~BTRequestStream() override { sent_reqs.clear(); }

        std::weak_ptr<BTRequestStream> weak_from_this()
        {
            return std::dynamic_pointer_cast<BTRequestStream>(shared_from_this());
        }

        void request(std::string endpoint, std::string body);

        void command(std::string endpoint, std::string body);

        void respond(int64_t rid, std::string body, bool error = false);

        void check_timeouts();

        void receive(bstring_view data) override;

        void closed(uint64_t app_code) override;

      private:
        void handle_bp_opt(std::function<void(message)> recv_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided recv callback!");
            recv_callback = std::move(recv_cb);
        }

        void handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided close callback!");
            close_callback = std::move(close_cb);
        }

        bool match(int64_t rid);

        void handle_input(message msg);

        void process_incoming(std::string_view req);

        std::shared_ptr<sent_request> make_request(std::string endpoint, std::string body);

        std::optional<sent_request> make_command(std::string endpoint, std::string body);

        std::optional<sent_request> make_response(int64_t rid, std::string body, bool error = false);

        size_t parse_length(std::string_view req);
    };
}  // namespace oxen::quic
