#include "btstream.hpp"

namespace oxen::quic
{
    message::message(BTRequestStream& bp, std::string req, bool is_error) :
            data{std::move(req)}, return_sender{bp.weak_from_this()}, cid{bp.conn_id()}, timed_out{is_error}
    {
        oxenc::bt_list_consumer btlc(data);

        req_type = btlc.consume_string_view();
        req_id = btlc.consume_integer<int64_t>();

        if (req_type == "C")
            ep = btlc.consume_string_view();
        else if (req_type == "E")
            is_error = true;

        req_body = btlc.consume_string_view();
    }

    void message::respond(std::string body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto ptr = return_sender.lock())
            ptr->respond(req_id, std::move(body), error);
    }

    void BTRequestStream::respond(int64_t rid, std::string body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        auto req = make_response(rid, std::move(body), error);

        if (req)
            send(std::move(*req).payload());
        else
            throw std::invalid_argument{"Invalid response!"};
    }

    void BTRequestStream::check_timeouts()
    {
        const auto now = get_time();

        do
        {
            auto& f = sent_reqs.front();

            if (f->is_expired(now))
            {
                f->cb(f->to_message(true));
                sent_reqs.pop_front();
            }
            else
                return;

        } while (not sent_reqs.empty());
    }

    void BTRequestStream::receive(bstring_view data)
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

    void BTRequestStream::closed(uint64_t app_code)
    {
        log::info(bp_cat, "bparser close callback called!");
        close_callback(*this, app_code);
    }

    void BTRequestStream::register_command(std::string ep, std::function<void(message)> func)
    {
        endpoint.call([&]() { func_map[std::move(ep)] = std::move(func); });
    }

    void BTRequestStream::handle_input(message msg)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        if (msg.req_type == "R" || msg.req_type == "E")
        {
            // Iterate using forward iterators, s.t. we go highest (newest) rids to lowest (oldest) rids.
            // As a result, our comparator checks if the sent request ID is greater thanthan the target rid
            auto itr = std::lower_bound(
                    sent_reqs.begin(),
                    sent_reqs.end(),
                    msg.req_id,
                    [](const std::shared_ptr<sent_request>& sr, int64_t rid) { return sr->req_id > rid; });

            if (itr != sent_reqs.end() and itr->get()->req_id == msg.req_id)
            {
                log::debug(bp_cat, "Successfully matched response to sent request!");
                itr->get()->cb(std::move(msg));
                sent_reqs.erase(itr);
                return;
            }
        }

        if (auto itr = func_map.find(msg.endpoint_str()); itr != func_map.end())
        {
            log::debug(bp_cat, "Executing request endpoint {}", msg.endpoint());
            itr->second(std::move(msg));
        }
    }

    void BTRequestStream::process_incoming(std::string_view req)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        while (not req.empty())
        {
            if (current_len == 0)
            {
                size_t consumed = 0;

                if (not size_buf.empty())
                {
                    size_t prev_len = size_buf.size();
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

    std::optional<sent_request> BTRequestStream::make_response(int64_t rid, std::string body, bool error)
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
    size_t BTRequestStream::parse_length(std::string_view req)
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
}  // namespace oxen::quic
