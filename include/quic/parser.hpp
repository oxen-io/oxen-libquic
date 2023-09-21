#include <oxenc/bt.h>

#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline auto bp_cat = oxen::log::Cat("bparser");

    using time_point = std::chrono::steady_clock::time_point;

    // timeout is used for sent requests awaiting responses
    const std::chrono::seconds TIMEOUT{10};

    // request sizes
    inline constexpr long long MAX_REQ_LEN = 10_M;

    // Application error
    inline constexpr uint64_t BPARSER_EXCEPTION = (1ULL << 60) + 69;

    struct message
    {
        std::string data;
        std::string_view req_type;
        std::string_view req_id;
        std::string_view endpoint;
        std::string_view req_body;

        bool error{false};

        message(std::string req, bool is_error = false) : data{std::move(req)}, error{is_error}
        {
            oxenc::bt_list_consumer btlc(data);

            req_type = btlc.consume_string_view();
            req_id = btlc.consume_string_view();

            if (req_type == "Q" || req_type == "C")
                endpoint = btlc.consume_string_view();

            req_body = btlc.consume_string_view();
        }

        std::string rid() { return std::string{req_id}; }
        std::string_view view() { return {data}; }
    };

    struct sent_request
    {
        // parsed request data
        std::string data;
        std::string req_id;

        // total length of the request; is at the beginning of the request
        size_t total_len;

        std::chrono::steady_clock::time_point req_time;
        std::chrono::steady_clock::time_point timeout;

        bool is_empty() const { return data.empty() && total_len == 0; }

        explicit sent_request(std::string d, std::string rid) : req_id{std::move(rid)}
        {
            total_len = d.length();
            data.reserve(data.length() + total_len);
            data += std::to_string(total_len);
            data += ':';
            data.append(d);

            req_time = get_time();
            timeout = req_time + TIMEOUT;
        }

        message to_message() { return {data}; }

        std::string_view view() { return {data}; }
        std::string&& payload() { return std::move(data); }
    };

    class bparser : public Stream
    {
      private:
        // outgoing requests awaiting response
        std::map<std::chrono::steady_clock::time_point, std::shared_ptr<sent_request>> sent_reqs;

        std::string buf;
        std::string size_buf;

        size_t current_len{0};

        std::atomic<int64_t> next_rid{0};

        std::function<void(Stream&, message)> recv_callback;

        std::function<void(Stream&, uint64_t)> close_callback = [this](Stream& s, uint64_t ec) {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);
            sent_reqs.clear();
            s.close(io_error{ec});
        };

      public:
        template <typename... Opt>
        explicit bparser(Connection& _c, Endpoint& _e, Opt&&... opts) : Stream{_c, _e}
        {
            ((void)handle_bp_opt(std::forward<Opt>(opts)), ...);
        }

        void request(std::string endpoint, std::string body) override
        {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_request(std::move(endpoint), std::move(body));
            send(req->view());

            auto& sr = sent_reqs[req->timeout];
            sr = std::move(req);
        }

        void command(std::string endpoint, std::string body) override
        {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_command(std::move(endpoint), std::move(body));
            send(req->payload());
        }

        void respond(std::string rid, std::string body, bool error = false) override
        {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_response(std::move(rid), std::move(body), error);
            send(req->payload());
        }

        void receive(bstring_view data) override
        {
            log::info(bp_cat, "bparser recv data callback called!");
            log::debug(bp_cat, "Received data: {}", buffer_printer{data});

            try
            {
                process_incoming(to_sv(data));
            }
            catch (std::exception& e)
            {
                log::error(bp_cat, "Exception caught: {}", e.what());
            }
        }

        void closed(uint64_t app_code) override
        {
            log::info(bp_cat, "bparser close callback called!");
            close_callback(*this, app_code);
        }

        void check_timeouts() override
        {
            const auto& now = get_time();

            for (auto itr = sent_reqs.begin(); itr != sent_reqs.end();)
            {
                if (itr->first < now)
                    itr = sent_reqs.erase(itr);
                else
                    return;
            }
        }

      private:
        void handle_bp_opt(std::function<void(Stream&, message)> recv_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided recv callback!");
            recv_callback = std::move(recv_cb);
        }

        void handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided close callback!");
            close_callback = std::move(close_cb);
        }

        bool match(std::string_view rid)
        {
            log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

            for (auto& r : sent_reqs)
            {
                if (r.second->req_id == rid)
                {
                    log::debug(bp_cat, "Successfully matched response to sent request!");
                    sent_reqs.erase(r.first);
                    return true;
                }
            }

            return false;
        }

        void handle_input(message msg)
        {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);

            if (msg.req_type == "R" || msg.req_type == "E")
            {
                if (auto b = match(msg.req_id); not b)
                {
                    log::warning(bp_cat, "Error: could not match orphaned response!");
                    return;
                }
            }

            recv_callback(*this, std::move(msg));
        }

        void process_incoming(std::string_view req)
        {
            log::debug(bp_cat, "{} called", __PRETTY_FUNCTION__);

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
                        handle_input(message{std::move(buf)});
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
                    handle_input(message{std::move(buf)});
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
            std::string rid = std::to_string(++next_rid);

            try
            {
                btlp.append("Q");
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);

                auto req = std::make_shared<sent_request>(std::move(btlp).str(), rid);
                return req;
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing request encoding!");
            }

            return nullptr;
        }

        std::shared_ptr<sent_request> make_command(std::string endpoint, std::string body)
        {
            oxenc::bt_list_producer btlp;
            std::string rid = std::to_string(++next_rid);

            try
            {
                btlp.append("C");
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);

                auto req = std::make_shared<sent_request>(std::move(btlp).str(), rid);
                return req;
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing command encoding!");
            }

            return nullptr;
        }

        std::shared_ptr<sent_request> make_response(std::string rid, std::string body, bool error = false)
        {
            oxenc::bt_list_producer btlp;

            try
            {
                btlp.append(error ? "E" : "R");
                btlp.append(rid);
                btlp.append(body);

                auto req = std::make_shared<sent_request>(std::move(btlp).str(), rid);
                return req;
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid outgoing response encoding!");
            }

            return nullptr;
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
                close_callback(*this, BPARSER_EXCEPTION);
                throw std::invalid_argument{"Invalid incoming request encoding!"};
            }

            if (current_len > MAX_REQ_LEN)
            {
                close_callback(*this, BPARSER_EXCEPTION);
                throw std::invalid_argument{"Request exceeds maximum size!"};
            }

            return pos + 1;
        }
    };
}  // namespace oxen::quic
