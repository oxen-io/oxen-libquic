#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    struct request_t;

    using time_point = std::chrono::steady_clock::time_point;

    // timeout is used for whole requests awaiting responses
    const std::chrono::milliseconds TIMEOUT{1000};

    // request sizes
    inline constexpr size_t RID_LENGTH{15};
    inline constexpr size_t TYPE_LENGTH{1};

    inline constexpr std::byte DELIMITER{':'};
    
    inline const bstring RID_PREFIX{std::byte{15}, std::byte{':'}};

    inline std::basic_string<std::byte> operator""_bs(const char* __str, size_t __len) noexcept
    {
        return std::basic_string<std::byte>(reinterpret_cast<const std::byte*>(__str), __len);
    }

    enum class request_type
    {
        INCOMPLETE = 0, REQUEST = 1, RESPONSE = 2, COMMAND = 3, ERROR = 4
    };

    inline request_type translate_req_type(std::byte b)
    {
        switch (b)
        {
            case std::byte{'Q'}:
                return request_type::REQUEST;
            case std::byte{'C'}:
                return request_type::COMMAND;
            case std::byte{'R'}:
                return request_type::RESPONSE;
            case std::byte{'E'}:
                return request_type::ERROR;
            default:
                return request_type::INCOMPLETE;
        }
    }

    inline std::byte revert_req_type(request_type rt)
    {
        switch (rt)
        {
            case request_type::REQUEST:
                return std::byte{'Q'};
            case request_type::COMMAND:
                return std::byte{'C'};
            case request_type::RESPONSE:
                return std::byte{'R'};
            case request_type::ERROR:
                return std::byte{'E'};
            case request_type::INCOMPLETE:
                throw std::invalid_argument{"This method is for construction of outgoing requests!"};
        }
    }

    struct message
    {
        bstring data{};
        bstring endpoint{};
        bstring req_id{};
        bstring req_body{};

        std::shared_ptr<Stream> stream;

        message(
                bstring d, 
                bstring_view ep, 
                bstring_view rid, 
                bstring_view rbody, 
                std::shared_ptr<Stream>& s) : 
                data{d}, 
                endpoint{ep},
                req_id{rid},
                req_body{rbody},
                stream{s}
        {}

        bstring_view payload() const
        { return data; }
    };

    struct request_t
    {
        // parsed request data
        bstring data{};
        bstring_view data_view{};
        bstring_view req_id{};
        bstring_view req_endpoint{};
        bstring_view req_body{};

        // total length of the request; is at the beginning of the request
        size_t total_len{};
        // the total length currently received 
        size_t recv_len{};
        size_t currently_read{0};
        bool is_complete{false};   // this is a dumb name
        request_type type{request_type::INCOMPLETE};

        time_point req_time;
        time_point timeout;

        bstring_view rid()
        { return req_id; }

        bool is_empty() const
        { return data.empty() && total_len == 0; }

        void fill(bstring_view req, time_point tp)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            req_time = tp;
            data.append(req.data());
            data_view = {data};
            recv_len = data.length();

            if (!total_len)
            {
                if (auto r = parse_length(); not r)
                    return;
            }            

            if (type == request_type::INCOMPLETE)
            {
                if (auto r = parse_type(); not r)
                    return;
            }

            if (req_id.empty())
            {
                if (auto r = parse_req_id(); not r)
                    return;
            }

            // only parse endpoint for request/command messages
            if (type == request_type::COMMAND || type == request_type::REQUEST)
            {
                if (req_endpoint.empty())
                    if (auto r = parse_endpoint(); not r)
                        return;
            }

            // parse request body for all types
            if (req_body.empty())
                if (auto r = parse_body(); not r)
                    return;

            is_complete = true;
            timeout = req_time + TIMEOUT;
        }

        void populate(bstring req)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            data = req;
            data_view = {data};
            recv_len = data.length();

            if (auto r = parse_length(); not r)
                throw std::runtime_error{"Error: failed to populate outgoing request"};

            if (auto r = parse_type(); not r)
                throw std::runtime_error{"Error: failed to populate outgoing request"};

            if (auto r = parse_req_id(); not r)
                throw std::runtime_error{"Error: failed to populate outgoing request"};

            if (auto r = parse_endpoint(); not r)
                throw std::runtime_error{"Error: failed to populate outgoing request"};

            if (auto r = parse_body(); not r)
                throw std::runtime_error{"Error: failed to populate outgoing request"};

            is_complete = true;
            req_time = get_time();
            timeout = req_time + TIMEOUT;
        }

        message to_message(std::shared_ptr<Stream>& s)
        {
            return {data, req_endpoint, req_id, req_body, s};
        }

        explicit request_t() = default;

      private:
        bool parse_length()
        {
            auto pos = data.find_first_of(std::byte{':'});

            // request is incomplete with no readable request length
            if (data.at(pos) == data.back())
                return false;

            total_len = std::atoi(
                    reinterpret_cast<const char*>(data_view.substr(0, pos).data()));

            // erase outer encoding
            data.erase(0, pos+1);
            data_view.remove_prefix(pos);
            recv_len -= total_len + 1;  // remove one extra for the colon

            data.reserve(total_len);
            // set currently_read to 1 after req_len colon delimiter
            currently_read = pos + 1;

            return true;
        }

        bool parse_type()
        {
            // get pos starting at last read
            auto pos = data.find_first_of(std::byte{':'}, currently_read);

            // either we have no request type or it ends right after that colon
            if (pos + TYPE_LENGTH >= recv_len)
                return false;

            // advance to and get actual type value
            pos += 1;
            type = translate_req_type(data.at(pos));
            // set currently_read to current pos (1 after colon delimiter)
            currently_read = pos;

            return true;
        }

        bool parse_req_id()
        {
            // get pos starting at last read
            auto pos = data.find_first_of(std::byte{':'}, currently_read);

            // either we have no request_id or it ends right after that colon
            if (pos + RID_LENGTH >= recv_len)
                return false;

            // advance to and get actual rid value
            pos += 1;
            req_id = data_view.substr(currently_read + pos, RID_LENGTH);
            // set currently_read to after request_id (length value of next data field, dependent on request_type)
            currently_read = pos + RID_LENGTH;

            return true;
        }

        bool parse_endpoint()
        {
            // get pos starting at last read
            auto pos = data.find_first_of(std::byte{':'}, currently_read);

            // we are cut off in the middle of the endpoint data
            if (data.at(pos) == data.back())
                return false;

            // get the actual endpoint length, advance pos
            auto ep_len = std::atoi(
                    reinterpret_cast<const char*>(data_view.substr(currently_read, pos).data()));
            pos += 1;

            // capture endpoint values in view
            req_endpoint = data_view.substr(pos, ep_len);
            // set currently_read to after endpoint (length value of next data field, method_data)
            currently_read = pos + ep_len;

            return true;
        }

        // This is usable for any terminating data field. For requests and commands it is "DATAFORTHEMETHOD"; for
        // responses and errors it is "RESPONSEDATA" and "ERRORDATA"
        bool parse_body()
        {
            // get pos starting at last read
            auto pos = data.find_first_of(std::byte{':'}, currently_read);

            // we are cut off in the middle of the method data
            if (data.at(pos) == data.back())
                return false;

            // get the actual method length, advance pos
            auto m_len = std::atoi(
                    reinterpret_cast<const char*>(data_view.substr(currently_read, pos).data()));
            pos += 1;

            // capture endpoint values in view
            req_body = data_view.substr(pos, m_len);
            
            return true;
        }
    };
}   // namespace oxen::quic

namespace std
{
    // not needed anymore...?
    template <>
    struct hash<oxen::quic::request_t>
    {
        size_t operator()(const oxen::quic::request_t& bp) const
        {
            return hash<size_t>{}(static_cast<size_t>(bp.req_time.time_since_epoch().count()));
        }
    };
}   // namespace std

namespace oxen::quic
{
    class bparser
    {
      private:
        // quic::stream object housing bparser
        std::shared_ptr<Stream> stream;

        // fully parsed requests
        std::unordered_map<uint64_t, std::shared_ptr<request_t>> sent_reqs;

        // we only have one partial request at a time
        std::shared_ptr<request_t> current_req{};

        // tracks if we are in the process of receiving a request
        bool in_progress{false};

        std::optional<message> match(std::shared_ptr<request_t>& req)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            const auto& rid = req->req_id;

            for (auto& r : sent_reqs)
            {
                if (r.second->req_id == rid)
                {
                    auto& matched = r.second;
                    // copy over needed info from initial request to make message
                    req->req_endpoint = matched->req_endpoint;
                    req->req_body = matched->req_body;

                    // create message object prior to resetting initial request we copied bviews from
                    auto msg = req->to_message(stream);
                    sent_reqs.erase(r.first);
                    return msg;
                }
            }

            return std::nullopt;
        }

        std::optional<message> intake(bstring_view data, time_point ts)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            
            current_req->fill(data, ts);

            if (not current_req->is_complete)
            {
                in_progress = true;
                return std::nullopt;
            }

            in_progress = false;

            auto& rt = current_req->type;
            if (rt == request_type::INCOMPLETE)
                throw std::runtime_error{"Error: incomplete request should not be parsed as complete"};

            auto msg = (rt == request_type::RESPONSE || rt == request_type::ERROR) ?
                    match(current_req) :
                    current_req->to_message(stream);

            current_req.reset();
            return msg;
        }

        std::shared_ptr<request_t> make_request(bstring endpoint, bstring body, request_type rtype)
        {
            // request type
            bstring r = "l1:"_bs;
            r.push_back(revert_req_type(rtype));

            // request ID
            bstring rid = "111112222233333"_bs;    // replace with libsodium function call
            r.push_back(std::byte{15});
            r.push_back(DELIMITER);
            r.append(rid);

            // endpoint data
            r.push_back(std::byte{(uint8_t)endpoint.length()});
            r.push_back(DELIMITER);
            r.append(endpoint);

            // request body
            r.push_back(std::byte{(uint8_t)body.length()});
            r.push_back(DELIMITER);
            r.append(body);
            r.push_back(std::byte{'e'});

            // outer encoding
            size_t req_len = r.length();
            r.insert(r.begin(), DELIMITER);
            r.insert(r.begin(), std::byte{(uint8_t(req_len))});

            auto req = std::make_shared<request_t>();
            req->populate(r);
            return req;
        }
    
      public:
        void request(bstring endpoint, bstring body)
        {
            log::critical(log_cat, "{} called", __PRETTY_FUNCTION__);
            
            auto req = make_request(std::move(endpoint), std::move(body), request_type::REQUEST);

            stream->send(req->data);

            auto& sr = sent_reqs[req->timeout.time_since_epoch().count()];
            sr = std::move(req);
        }

        void command(bstring endpoint, bstring body)
        {
            log::critical(log_cat, "{} called", __PRETTY_FUNCTION__);

            auto req = make_request(std::move(endpoint), std::move(body), request_type::COMMAND);
            stream->send(req->data);
        }

        // allows the bparser to be passed to a stream and used like a callback
        void operator()(Stream&, bstring_view dat)
        {
            log::debug(log_cat, "bparser recv data callback called!");

            auto maybe_msg = intake(dat, get_time());

            if (maybe_msg)
                log::debug(log_cat, "bparser returned message: {}", buffer_printer{maybe_msg->payload()});
            else
                log::debug(log_cat, "bparser returned nullopt");
        }
        void operator()(Stream&, uint64_t) 
        {
            log::debug(log_cat, "bparser close callback called!");
        }
    };
}   // namespace oxen::quic
