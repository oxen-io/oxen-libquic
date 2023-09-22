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

        explicit sent_request(BTRequestStream& bp, std::string_view d, int64_t rid) : req_id{rid}, return_sender{bp}
        {
            total_len = d.length();
            data = oxenc::bt_serialize(d);
            req_time = get_time();
            timeout = req_time + TIMEOUT;
        }

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

        friend class sent_request;
        std::function<void(message)> recv_callback;

      public:
        template <typename... Opt>
        explicit BTRequestStream(Connection& _c, Endpoint& _e, Opt&&... opts) : Stream{_c, _e}
        {
            ((void)handle_bp_opt(std::forward<Opt>(opts)), ...);
        }

        ~BTRequestStream() { sent_reqs.clear(); }

        std::weak_ptr<BTRequestStream> weak_from_this()
        {
            return std::dynamic_pointer_cast<BTRequestStream>(shared_from_this());
        }

        void request(std::string endpoint, std::string body)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_request(std::move(endpoint), std::move(body));
            send(req->view());

            sent_reqs.push_back(std::move(req));
        }

        void command(std::string endpoint, std::string body)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_command(std::move(endpoint), std::move(body));

            if (req)
                send(std::move(*req).payload());
            else
                throw std::invalid_argument{"Invalid command!"};
        }

        void respond(int64_t rid, std::string body, bool error = false)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_response(rid, std::move(body), error);

            if (req)
                send(std::move(*req).payload());
            else
                throw std::invalid_argument{"Invalid response!"};
        }

        void check_timeouts()
        {
            const auto now = get_time();

            do
            {
                auto& f = sent_reqs.front();

                if (f->is_expired(now))
                {
                    recv_callback(f->to_message(true));
                    sent_reqs.pop_front();
                }
                else
                    return;

            } while (not sent_reqs.empty());
        }

        void receive(bstring_view data) override
        {
            log::trace(bp_cat, "bparser recv data callback called!");

            if (is_closing())
                return;

            try
            {
                process_incoming(to_sv(data));
            }
            catch (const std::exception& e)
            {
                log::error(bp_cat, "Exception caught: {}", e.what());
                close(io_error{BPARSER_EXCEPTION});
            }
        }

        void closed(uint64_t app_code) override
        {
            log::info(bp_cat, "bparser close callback called!");
            close_callback(*this, app_code);
        }

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

        bool match(int64_t rid)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            // Iterate using forward iterators, s.t. we go highest (newest) rids to lowest (oldest) rids.
            // As a result, our comparator checks if the sent request ID is greater thanthan the target rid
            auto itr = std::lower_bound(
                    sent_reqs.begin(), sent_reqs.end(), rid, [](const std::shared_ptr<sent_request>& sr, int64_t rid) {
                        return sr->req_id > rid;
                    });

            if (itr != sent_reqs.end() and itr->get()->req_id == rid)
            {
                log::debug(bp_cat, "Successfully matched response to sent request!");
                sent_reqs.erase(itr);
                return true;
            }

            return false;
        }

        void handle_input(message msg)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            if (msg.req_type == "R" || msg.req_type == "E")
            {
                if (auto b = match(msg.req_id); not b)
                {
                    log::warning(bp_cat, "Error: could not match orphaned response!");
                    return;
                }
            }

            recv_callback(std::move(msg));
        }

        void process_incoming(std::string_view req)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            while (not req.empty())
            {
                if (current_len == 0)
                {
                    int consumed = 0;

                    if (not size_buf.empty())
                    {
                        int prev_len = size_buf.size();
                        size_buf += req.substr(0, 15);

                        consumed = parse_length(size_buf);

                        if (consumed == 0)
                            return;

                        size_buf.clear();
                        req.remove_prefix(consumed - prev_len);
                    }
                    else
                    {
                        consumed = parse_length(req);
                        if (consumed == 0)
                        {
                            size_buf += req;
                            return;
                        }

                        req.remove_prefix(consumed);
                    }

                    if (req.size() >= current_len)
                    {
                        buf += req.substr(0, current_len);
                        handle_input(message{*this, std::move(buf)});
                        req.remove_prefix(current_len);

                        current_len = 0;
                        continue;
                    }

                    buf.reserve(current_len);
                    buf += req;
                    return;
                }

                auto r_size = req.size() + buf.size();

                if (r_size >= current_len)
                {
                    buf += req.substr(0, r_size);
                    req.remove_prefix(r_size);
                    handle_input(message{*this, std::move(buf)});
                    current_len = 0;
                    continue;
                }

                buf += req;
                return;
            }
        }

        std::shared_ptr<sent_request> make_request(std::string endpoint, std::string body)
        {
            oxenc::bt_list_producer btlp;
            auto rid = ++next_rid;

            try
            {
                btlp.append("Q");
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);

                return std::make_shared<sent_request>(*this, std::move(btlp).str(), rid);
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing request encoding!");
            }

            return nullptr;
        }

        std::optional<sent_request> make_command(std::string endpoint, std::string body)
        {
            oxenc::bt_list_producer btlp;
            auto rid = ++next_rid;

            try
            {
                btlp.append("C");
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);

                return sent_request{*this, btlp.view(), rid};
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing command encoding!");
            }

            return std::nullopt;
        }

        std::optional<sent_request> make_response(int64_t rid, std::string body, bool error = false)
        {
            oxenc::bt_list_producer btlp;

            try
            {
                btlp.append(error ? "E" : "R");
                btlp.append(rid);
                btlp.append(body);

                return sent_request{*this, btlp.view(), rid};
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing response encoding!");
            }

            return std::nullopt;
        }

        /** Returns:
                0: length was incomplete
                >0: number of characters (including colon) parsed from front of req

            Error:
                throws on invalid value
        */
        int parse_length(std::string_view req)
        {
            auto pos = req.find_first_of(':');

            // request is incomplete with no readable request length
            if (req.at(pos) == req.back())
                return 0;

            auto [ptr, ec] = std::from_chars(req.data(), req.data() + pos, current_len);

            if (ec != std::errc())
            {
                close(io_error{BPARSER_EXCEPTION});
                throw std::invalid_argument{"Invalid incoming request encoding!"};
            }

            if (current_len > MAX_REQ_LEN)
            {
                close(io_error{BPARSER_EXCEPTION});
                throw std::invalid_argument{"Request exceeds maximum size!"};
            }

            return pos + 1;
        }
    };

    inline message::message(BTRequestStream& bp, std::string req, bool is_error) :
            data{std::move(req)}, timed_out{is_error}, return_sender{bp.weak_from_this()}
    {
        oxenc::bt_list_consumer btlc(data);

        req_type = btlc.consume_string_view();
        req_id = btlc.consume_integer<int64_t>();

        if (req_type == "Q" || req_type == "C")
            endpoint = btlc.consume_string_view();

        req_body = btlc.consume_string_view();
    }

    inline void message::respond(int64_t rid, std::string body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        return_sender.lock()->respond(rid, std::move(body), error);
    }
}  // namespace oxen::quic
