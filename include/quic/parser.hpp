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
    inline constexpr long long MAX_REQ_LEN{10000000};

    // Application error
    inline constexpr uint64_t BPARSER_EXCEPTION = (1ULL << 62) + 69;

    inline std::basic_string<std::byte> operator""_bs(const char* __str, size_t __len) noexcept
    {
        return std::basic_string<std::byte>(reinterpret_cast<const std::byte*>(__str), __len);
    }

    inline std::string_view to_sv(bstring_view x)
    {
        return {reinterpret_cast<const char*>(x.data()), x.size()};
    }

    enum class request_type { INCOMPLETE = 0, REQUEST = 1, RESPONSE = 2, COMMAND = 3, ERROR = 4 };

    inline std::string encode_req_type(request_type rt)
    {
        switch (rt)
        {
            case request_type::REQUEST:
                return "Q";
            case request_type::COMMAND:
                return "C";
            case request_type::RESPONSE:
                return "R";
            case request_type::ERROR:
                return "E";
            case request_type::INCOMPLETE:
                throw std::invalid_argument{"This method is for construction of outgoing requests!"};
        }
    }

    struct message
    {
        std::string data;
        std::string_view req_type;
        std::string_view req_id;
        std::string_view endpoint;
        std::string_view req_body;

        std::shared_ptr<Stream> stream;

        message(std::string req, std::shared_ptr<Stream>& s) : data{std::move(req)}, stream{s}
        {
            oxenc::bt_list_consumer btlc(data);

            try
            {
                req_type = btlc.consume_string_view();
                req_id = btlc.consume_string_view();

                if (req_type == "Q" || req_type == "C")
                    endpoint = btlc.consume_string_view();

                req_body = btlc.consume_string_view();
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid request body!");
            }
        }
    };

    struct sent_request
    {
        // parsed request data
        std::string data;
        std::string_view req_id;

        // total length of the request; is at the beginning of the request
        size_t total_len;

        uint64_t req_time;
        uint64_t timeout;

        bool is_empty() const { return data.empty() && total_len == 0; }

        explicit sent_request(std::string d, std::string rid) : req_id{std::move(rid)}
        {
            total_len = d.length();
            data += std::to_string(total_len);
            data += ':';
            data.reserve(data.length() + total_len);
            data.append(d);

            req_time = get_time().time_since_epoch().count();
            timeout = req_time + TIMEOUT.count();
        }

        message to_message(std::shared_ptr<Stream>& s) { return {data, s}; }

        std::string_view payload() { return data; }
    };
}  // namespace oxen::quic

namespace std
{
    // not needed anymore...?
    template <>
    struct hash<oxen::quic::sent_request>
    {
        size_t operator()(const oxen::quic::sent_request& bp) const
        {
            return hash<size_t>{}(static_cast<size_t>(bp.req_time));
        }
    };
}  // namespace std

namespace oxen::quic
{
    class bparser
    {
      private:
        // quic::stream object housing bparser
        std::shared_ptr<Stream> stream;

        // outgoing requests
        std::unordered_map<uint64_t, std::shared_ptr<sent_request>> sent_reqs;

        std::string buf;
        std::string size_buf;

        size_t current_len{0};

        std::function<void(message)> recv_callback;

        std::function<void(Stream&, uint64_t)> close_callback = [](Stream& s, uint64_t ec) {
            log::critical(bp_cat, "{} called", __PRETTY_FUNCTION__);
            s.close(ec);
        };

      public:
        template <typename... Opt>
        explicit bparser(std::shared_ptr<Stream>& s, Opt&&... opts) : stream{s}
        {
            ((void)handle_bp_opt(std::forward<Opt>(opts)), ...);
        }

        void request(std::string endpoint, std::string body)
        {
            log::critical(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_request(std::move(endpoint), std::move(body), request_type::REQUEST);

            stream->send(req->payload());

            auto& sr = sent_reqs[req->timeout];
            sr = std::move(req);
        }

        void command(std::string endpoint, std::string body)
        {
            log::critical(bp_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_request(std::move(endpoint), std::move(body), request_type::COMMAND);
            stream->send(req->payload());
        }

        // allows the bparser to be passed to a stream and used like a callback
        void operator()(Stream&, bstring_view dat)
        {
            log::debug(bp_cat, "bparser recv data callback called!");
            process_incoming(to_sv(dat));
        }
        void operator()(Stream& s, uint64_t ec)
        {
            log::debug(bp_cat, "bparser close callback called!");
            close_callback(s, ec);
        }

      private:
        void handle_bp_opt(std::function<void(message)> recv_cb)
        {
            log::debug(bp_cat, "Bparser set user-provided recv callback!");
            recv_callback = std::move(recv_cb);
        }

        void handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb)
        {
            log::trace(bp_cat, "Bparser set user-provided close callback!");
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
            if (msg.req_type == "R" || msg.req_type == "E")
            {
                if (auto b = match(msg.req_id); not b)
                {
                    log::critical(bp_cat, "Error: could not match orphaned response");
                    close_callback(*stream, BPARSER_EXCEPTION);
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
                        handle_input(message{std::move(buf), stream});
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
                    handle_input(message{std::move(buf), stream});
                    current_len = 0;
                    continue;
                }

                buf += req;
                return;
            }
        }

        std::shared_ptr<sent_request> make_request(std::string endpoint, std::string body, request_type rtype)
        {
            oxenc::bt_list_producer btlp;
            std::string rid = "111112222233333"s;  // replace with libsodium function call

            try
            {
                btlp.append(encode_req_type(rtype));
                btlp.append(rid);
                btlp.append(endpoint);
                btlp.append(body);
            }
            catch (...)
            {
                log::critical(bp_cat, "Invalid request encoding!");
                close_callback(*stream, BPARSER_EXCEPTION);
            }

            auto req = std::make_shared<sent_request>(std::move(btlp).str(), rid);

            return req;
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
                close_callback(*stream, BPARSER_EXCEPTION);
                throw std::invalid_argument{"Invalid request encoding!"};
            }

            if (current_len > MAX_REQ_LEN)
            {
                close_callback(*stream, BPARSER_EXCEPTION);
                throw std::invalid_argument{"Request exceeds maximum size!"};
            }

            return pos + 1;
        }
    };
}  // namespace oxen::quic
