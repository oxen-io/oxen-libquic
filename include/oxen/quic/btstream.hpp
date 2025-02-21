#include "endpoint.hpp"
#include "stream.hpp"
#include "utils.hpp"

#include <oxenc/bt.h>

namespace oxen::quic
{
    // timeout is used for sent requests awaiting responses
    inline constexpr std::chrono::seconds DEFAULT_TIMEOUT{10s};

    // request sizes
    inline constexpr long long MAX_REQ_LEN = 10_M;

    // maximum length of the bencoded request length string, including the `:`.  This must be large
    // enough to hold `MAX_REQ_LEN` followed by a `:`.
    inline constexpr size_t MAX_REQ_LEN_ENCODED = 9;  // "10000000:"

    class BTRequestStream;

    // Exception type to throw from a handler to have a method-not-found error returned as a
    // response to the message.  The `what()` value is not actually used: we send back a string that
    // includes the requested method name in the error.  The main use of this exception is when
    // using a generic handler to use the exact same error behaviour as if `register_command` were
    // being used and the command didn't exist, but individual handlers could use it as well.
    class no_such_endpoint : public std::exception
    {
        const char* what() const noexcept override { return "endpoint does not exist"; }
    };

    struct message
    {
        friend class BTRequestStream;
        friend struct sent_request;

      private:
        int64_t req_id;
        std::vector<std::byte> data;

        // We keep the locations of variables fields as relative positions inside `data` *rather*
        // than using std::string_view members because the string_views are more difficult to
        // maintain when the object gets moved or copied.
        using substr_location = std::pair<std::ptrdiff_t, std::size_t>;
        substr_location req_type{};
        substr_location ep{};
        substr_location req_body{};

        std::weak_ptr<BTRequestStream> return_sender;
        ConnectionID _rid;

        // - `is_timeout` should be true if this is being constructed as a non-response because we
        //   didn't get any reply from the other side in time.  This *can* happen earlier than the
        //   requested timeout in cases where we detect early that the response cannot arrive, such
        //   as the connection closing.
        message(BTRequestStream& bp, std::vector<std::byte> req, bool is_timeout = false);

      public:
        inline static constexpr auto TYPE_REPLY = "R"sv;
        inline static constexpr auto TYPE_ERROR = "E"sv;
        inline static constexpr auto TYPE_COMMAND = "C"sv;

        void respond(bspan body, bool error = false) const;
        void respond(std::string_view body, bool error = false) const { respond(str_to_bspan(body), error); }

        const bool timed_out{false};
        bool is_error() const { return type() == TYPE_ERROR; }

        //  To be used to determine if the message was a result of an error or timeout; equivalent
        //  to checking that both .timed_out and .is_error() are false.
        //
        //  void f(const message& m)
        //  {
        //      if (not m.timed_out and not m.is_error)
        //      { // success logic }
        //      ... // is identical to:
        //      if (m)
        //      { // success logic }
        //  }
        explicit operator bool() const { return !timed_out && !is_error(); }

        template <oxenc::basic_char Char = char>
        std::span<const Char> span() const
        {
            return {reinterpret_cast<const Char*>(data.data()), data.size()};
        }

        int64_t rid() const { return req_id; }
        std::string_view type() const
        {
            return {reinterpret_cast<const char*>(data.data()) + req_type.first, req_type.second};
        }
        std::string_view endpoint() const { return {reinterpret_cast<const char*>(data.data()) + ep.first, ep.second}; }
        std::string endpoint_str() const { return std::string{endpoint()}; }

        template <oxenc::basic_char Char = char>
        std::basic_string_view<Char> body() const
        {
            return {reinterpret_cast<const Char*>(data.data()) + req_body.first, req_body.second};
        }

        template <oxenc::basic_char Char = char>
        std::basic_string<Char> body_str() const
        {
            return std::basic_string<Char>{body<Char>()};
        }

        const ConnectionID& conn_rid() const { return _rid; }

        std::shared_ptr<BTRequestStream> stream() const
        {
            if (auto ptr = return_sender.lock())
                return ptr;

            throw std::runtime_error{"Cannot access expired pointer to BT stream!"};
        }
    };

    struct sent_request
    {
        // parsed request data
        int64_t req_id;
        std::string data;
        std::function<void(message)> cb = nullptr;
        BTRequestStream& return_sender;

        // total length of the request; is at the beginning of the request
        size_t total_len;

        time_point req_time;
        time_point expiry;
        std::optional<std::chrono::milliseconds> timeout;

        bool is_empty() const { return data.empty() && total_len == 0; }

        template <typename... Opt>
        sent_request(BTRequestStream& bp, std::string_view d, int64_t rid, Opt&&... opts) :
                req_id{rid},
                data{oxenc::bt_serialize(d)},
                return_sender{bp},
                total_len{data.size()},
                req_time{get_time()},
                expiry{req_time}
        {
            if (total_len > MAX_REQ_LEN)
                throw std::invalid_argument{"Request body too long!"};

            ((void)handle_req_opts(std::forward<Opt>(opts)), ...);
            expiry += timeout.value_or(DEFAULT_TIMEOUT);
        }

        bool is_expired(time_point now) const { return expiry < now; }

        message to_timeout() && { return {return_sender, {}, true}; }

      private:
        void handle_req_opts(std::function<void(message)> func) { cb = std::move(func); }
        void handle_req_opts(std::chrono::milliseconds exp) { timeout = exp; }

        template <typename Opt>
        void handle_req_opts(std::optional<Opt> option)
        {
            if (option)
                handle_req_opts(std::move(*option));
        }
    };

    class BTRequestStream : public Stream
    {
        friend class TestHelper;

      private:
        // outgoing requests awaiting response
        // We use shared_ptr's so we can lambda capture it, though it is not actually shared
        std::deque<std::shared_ptr<sent_request>> sent_reqs;

        std::unordered_map<std::string, std::function<void(message)>> func_map;
        std::function<void(message)> generic_handler;

        std::vector<std::byte> buf;
        std::string size_buf;

        size_t current_len{0};

        std::atomic<int64_t> next_rid{0};

        friend struct sent_request;
        friend class Network;
        friend class Loop;

      protected:
        template <typename... Opt>
        explicit BTRequestStream(Connection& _c, Endpoint& _e, Opt&&... opts) : Stream{_c, _e}
        {
            ((void)handle_bp_opt(std::forward<Opt>(opts)), ...);
        }

      public:
        std::weak_ptr<BTRequestStream> weak_from_this()
        {
            return std::dynamic_pointer_cast<BTRequestStream>(shared_from_this());
        }

        /** API: ::command

            Invokes a remote RPC endpoint. The user can provide a callback if they are expecting
            a response, making this a "request." Also, a timeout can be provided to set a specific
            expiry time for the request.

            Parameters:
                std::string endpoint - remote RPC endpoint to be called
                std::string body - remote RPC endpoint body to be called
                Opt&&... opts:
                    std::function<void(message)> cb - callback to be executed if expecting response
                    std::chrono::milliseconds timeout - request timeout (defaults to 10 seconds)
        */
        template <typename... Opt>
        void command(std::string ep, bspan body, Opt&&... opts)
        {
            auto rid = next_rid++;
            auto req = std::make_shared<sent_request>(*this, encode_command(ep, rid, body), rid, std::forward<Opt>(opts)...);

            if (req->cb)
                endpoint.call([this, r = std::move(req)]() mutable {
                    if (auto* req = add_sent_request(std::move(r)))
                        send(std::move(req->data));
                });
            else
                send(std::move(*req).data);
        }
        // Same as above, but takes a regular string_view
        template <typename... Opt>
        void command(std::string ep, std::string_view body, Opt&&... opts)
        {
            command(std::move(ep), str_to_bspan(body), std::forward<Opt>(opts)...);
        }

        void respond(int64_t rid, bspan body, bool error = false);

        /// Registers an individual endpoint to be recognized by this BTRequestStream object.  Can be
        /// called multiple times to set up multiple commands.  See also register_generic_handler.
        void register_handler(std::string endpoint, std::function<void(message)>);

        /// Registered (or replaces) the generic handler that is invoked if the requested endpoint
        /// does not match any endpoint set up with `register_handler`.  If no individual
        /// `register_handler` endpoints are set up at all then this becomes the single callback to
        /// invoke for all incoming commands.  This handler should throw a `no_such_endpoint`
        /// exception if the endpoint in this message should be considered not found.
        void register_generic_handler(std::function<void(message)> request_handler);

        /// Returns the number of requests/commands that are pending outbound transmission. These have
        /// NOT been sent yet, rather they have been queued by the application
        size_t num_pending() const;

        /// Returns the number of sent requests awaiting response
        size_t num_awaiting_response() const;

      protected:
        void check_timeouts() override;
        void check_timeouts(std::optional<std::chrono::steady_clock::time_point> now);

        void receive(bspan data) override;

        void closed(uint64_t app_code) override;

      private:
        // Optional constructor argument: stream close callback
        void handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb);

        // Optional constructor argument: generic request handler.  Providing it in the constructor
        // is equivalent to calling register_command_fallback() with the lambda.
        void handle_bp_opt(std::function<void(message m)> request_handler);

        void handle_input(message msg);

        void process_incoming(bspan req);

        std::string encode_command(std::string_view endpoint, int64_t rid, bspan body);

        std::string encode_response(int64_t rid, bspan body, bool error);

        sent_request* add_sent_request(std::shared_ptr<sent_request> req);

        size_t parse_length(std::string_view req);

        size_t num_pending_impl() const { return user_buffers.size(); }

        size_t num_awaiting_response_impl() const { return sent_reqs.size(); }
    };
}  // namespace oxen::quic
