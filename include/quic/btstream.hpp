#include <oxenc/bt.h>

#include "endpoint.hpp"
#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline auto bp_cat = oxen::log::Cat("bparser");

    using time_point = std::chrono::steady_clock::time_point;

    // timeout is used for sent requests awaiting responses
    inline constexpr std::chrono::seconds DEFAULT_TIMEOUT{10s};

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
        std::string_view ep;
        std::string_view req_body;
        std::weak_ptr<BTRequestStream> return_sender;
        ConnectionID cid;

      public:
        message(BTRequestStream& bp, std::string req, bool is_error = false);

        void respond(std::string body, bool error = false);

        bool timed_out{false};
        bool is_error{false};

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
        operator bool() const { return not timed_out && not is_error; }

        std::string_view view() const { return {data}; }

        int64_t rid() const { return req_id; }
        std::string_view type() const { return req_type; }
        std::string_view endpoint() const { return ep; }
        std::string_view body() const { return req_body; }
        std::string endpoint_str() const { return std::string{ep}; }
        std::string body_str() const { return std::string{req_body}; }
        const ConnectionID& scid() const { return cid; }

        std::shared_ptr<BTRequestStream> stream() const
        {
            if (return_sender.expired())
                throw std::runtime_error{"Cannot access expired pointer to BT stream!"};

            return return_sender.lock();
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

        std::chrono::steady_clock::time_point req_time;
        std::chrono::steady_clock::time_point expiry;
        std::optional<std::chrono::milliseconds> timeout;

        bool is_empty() const { return data.empty() && total_len == 0; }

        template <typename... Opt>
        sent_request(BTRequestStream& bp, std::string_view d, int64_t rid, Opt&&... opts) :
                req_id{rid}, return_sender{bp}, total_len{d.length()}, req_time{get_time()}, expiry{req_time}
        {
            if (total_len > MAX_REQ_LEN)
                throw std::invalid_argument{"Request body too long!"};

            ((void)handle_req_opts(std::forward<Opt>(opts)), ...);
            data = oxenc::bt_serialize(d);
            expiry += timeout.value_or(DEFAULT_TIMEOUT);
        }

        bool is_expired(std::chrono::steady_clock::time_point tp) const { return expiry < tp; }

        message to_message(bool timed_out = false) { return {return_sender, data, timed_out}; }

        std::string_view view() { return {data}; }
        std::string payload() && { return std::move(data); }

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
      private:
        // outgoing requests awaiting response
        // We use shared_ptr's so we can lambda capture it, though it is not actually shared
        std::deque<std::shared_ptr<sent_request>> sent_reqs;

        std::unordered_map<std::string, std::function<void(message)>> func_map;

        std::string buf;
        std::string size_buf;

        size_t current_len{0};

        std::atomic<int64_t> next_rid{0};

        friend struct sent_request;

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
        void command(std::string ep, std::string body, Opt&&... opts)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_command(std::move(ep), std::move(body), std::forward<Opt>(opts)...);

            if (req->cb)
            {
                endpoint.call([this, r = std::move(req)]() {
                    sent_reqs.push_back(std::move(r));
                    send(sent_reqs.back()->view());
                });
            }
            else
                send(std::move(*req).payload());
        }

        void respond(int64_t rid, std::string body, bool error = false);

        void check_timeouts();

        void receive(bstring_view data) override;

        void closed(uint64_t app_code) override;

        void register_command(std::string endpoint, std::function<void(message)>);

        const Address& local() const { return conn.local(); }

        const Address& remote() const { return conn.remote(); }

      private:
        void handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided close callback!");
            close_callback = std::move(close_cb);
        }

        void handle_input(message msg);

        void process_incoming(std::string_view req);

        template <typename... Opt>
        std::shared_ptr<sent_request> make_command(std::string endpoint, std::string body, Opt&&... opts)
        {
            oxenc::bt_list_producer btlp;
            auto rid = ++next_rid;

            try
            {
                btlp.append("C");
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);

                return std::make_shared<sent_request>(*this, std::move(btlp).str(), rid, std::forward<Opt>(opts)...);
            }
            catch (const std::exception& e)
            {
                log::critical(bp_cat, "Invalid outgoing command encoding: {}", e.what());
                throw;
            }
        }

        std::optional<sent_request> make_response(int64_t rid, std::string body, bool error = false);

        size_t parse_length(std::string_view req);
    };
}  // namespace oxen::quic
