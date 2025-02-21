#include "btstream.hpp"

#include "internal.hpp"

#include <stdexcept>

namespace oxen::quic
{
    static std::pair<std::ptrdiff_t, std::size_t> get_location(std::vector<std::byte>& data, std::string_view substr)
    {
        auto* bsubstr = reinterpret_cast<const std::byte*>(substr.data());
        // Make sure the given substr actually is a substr of data:
        assert(bsubstr >= data.data() && bsubstr + substr.size() <= data.data() + data.size());
        return {bsubstr - data.data(), substr.size()};
    }

    message::message(BTRequestStream& bp, std::vector<std::byte> req, bool is_timeout) :
            data{std::move(req)}, return_sender{bp.weak_from_this()}, _rid{bp.reference_id}, timed_out{is_timeout}
    {
        if (!is_timeout)
        {
            oxenc::bt_list_consumer btlc(bspan{data});

            req_type = get_location(data, btlc.consume_string_view());
            req_id = btlc.consume_integer<int64_t>();

            if (type() == TYPE_COMMAND)
                ep = get_location(data, btlc.consume_string_view());

            req_body = get_location(data, btlc.consume_string_view());

            btlc.finish();
        }
    }

    void message::respond(bspan body, bool error) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto ptr = return_sender.lock())
            ptr->respond(req_id, body, error);
        else
            log::warning(log_cat, "BTRequestStream unable to send response: stream has gone away");
    }

    void BTRequestStream::handle_bp_opt(std::function<void(Stream&, uint64_t)> close_cb)
    {
        log::debug(log_cat, "Bparser set user-provided close callback!");
        close_callback = std::move(close_cb);
    }
    void BTRequestStream::handle_bp_opt(std::function<void(message m)> request_handler)
    {
        log::debug(log_cat, "Bparser set generic request handler");
        generic_handler = std::move(request_handler);
    }
    void BTRequestStream::respond(int64_t rid, bspan body, bool error)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        send(sent_request{*this, encode_response(rid, body, error), rid}.data);
    }

    void BTRequestStream::check_timeouts()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return check_timeouts(get_time());
    }

    void BTRequestStream::check_timeouts(std::optional<std::chrono::steady_clock::time_point> now)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        while (!sent_reqs.empty())
        {
            auto& f = *sent_reqs.front();
            if (now && !f.is_expired(*now))
                return;
            auto ptr = std::move(sent_reqs.front());
            sent_reqs.pop_front();

            try
            {
                f.cb(std::move(f).to_timeout());
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception from timeout response handler: {}", e.what());
            }
        }
    }

    void BTRequestStream::receive(bspan data)
    {
        log::trace(log_cat, "bparser recv data callback called!");

        if (is_closing())
            return;

        try
        {
            process_incoming(data);
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "Exception caught: {}", e.what());
            close(BPARSER_ERROR_EXCEPTION);
        }
    }

    void BTRequestStream::closed(uint64_t app_code)
    {
        log::debug(log_cat, "bparser closed with {}", quic_strerror(app_code));

        // First time out any pending requests, even if they haven't hit the timer, because we're
        // being closed and so they can never be answered.
        check_timeouts(std::nullopt);

        Stream::close(app_code);
    }

    void BTRequestStream::register_handler(std::string ep, std::function<void(message)> func)
    {
        endpoint.call(
                [this, ep = std::move(ep), func = std::move(func)]() mutable { func_map[std::move(ep)] = std::move(func); });
    }

    void BTRequestStream::register_generic_handler(std::function<void(message)> request_handler)
    {
        log::debug(log_cat, "Bparser set generic request handler");
        endpoint.call([this, func = std::move(request_handler)]() mutable { generic_handler = std::move(func); });
    }

    void BTRequestStream::handle_input(message msg)
    {
        log::trace(log_cat, "{} called to handle {} input", __PRETTY_FUNCTION__, msg.type());

        if (auto type = msg.type(); type == message::TYPE_REPLY || type == message::TYPE_ERROR)
        {
            log::debug(log_cat, "Looking for request with req_id={}", msg.req_id);
            // Iterate using forward iterators, s.t. we go highest (newest) rids to lowest (oldest) rids.
            // As a result, our comparator checks if the sent request ID is greater thanthan the target rid
            auto itr = std::lower_bound(
                    sent_reqs.begin(),
                    sent_reqs.end(),
                    msg.req_id,
                    [](const std::shared_ptr<sent_request>& sr, int64_t rid) { return sr->req_id < rid; });

            if (itr != sent_reqs.end())
            {
                log::debug(log_cat, "Successfully matched response (req_id={}) to sent request!", msg.req_id);
                auto req = std::move(*itr);
                sent_reqs.erase(itr);
                try
                {
                    req->cb(std::move(msg));
                }
                catch (const std::exception& e)
                {
                    log::error(log_cat, "Uncaught exception from response handler: {}", e.what());
                }
            }
            return;
        }

        // `msg` likely isn't valid in the exception handlers below, so extract what we need to
        // send a response anyway:
        const auto req_id = msg.req_id;
        const auto ep = msg.endpoint_str();
        try
        {
            if (!func_map.empty())
            {
                if (auto itr = func_map.find(ep); itr != func_map.end())
                {
                    log::debug(log_cat, "Executing request endpoint {}", msg.endpoint());
                    return itr->second(std::move(msg));
                }
            }
            if (generic_handler)
            {
                log::debug(log_cat, "Executing generic request handler for endpoint {}", msg.endpoint());
                return generic_handler(std::move(msg));
            }
            throw no_such_endpoint{};
        }
        catch (const no_such_endpoint&)
        {
            log::warning(log_cat, "No handler found for endpoint {}, returning error response", ep);
            respond(req_id, str_to_bspan("Invalid endpoint '{}'"_format(ep)), true);
        }
        catch (const std::exception& e)
        {
            log::error(
                    log_cat,
                    "Handler for {} threw an uncaught exception ({}); returning a generic error message",
                    ep,
                    e.what());
            respond(req_id, "An error occurred while processing the request"_bsp, true);
        }
    }

    void BTRequestStream::process_incoming(bspan req)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        while (not req.empty())
        {
            if (current_len == 0)
            {
                std::string_view sreq{reinterpret_cast<const char*>(req.data()), req.size()};
                size_t consumed;
                size_t prev_len = size_buf.size();
                if (prev_len)
                {
                    // We have some leftover digits in size_buf, so copy some more from the incoming
                    // data to make size_buf up to MAX_REQ_LEN_ENCODED long:
                    if (prev_len < MAX_REQ_LEN_ENCODED)
                        size_buf += sreq.substr(0, MAX_REQ_LEN_ENCODED - prev_len);

                    // Now see if we can parse a `N:` value out of it.
                    consumed = parse_length(size_buf);
                    // 0 means the : wasn't found *but* that the input value is still less than the
                    // max, so we've already appended it and can just wait for more data to append.
                    // (This case is rare; it would mean we only got a very small number of stream
                    // bytes).
                    if (consumed == 0)
                        return;

                    // Otherwise we successfully parsed the size, have updated current_len, and
                    // don't need the size buffer anymore:
                    size_buf.clear();
                }
                else
                {
                    // With no initial buffer we can just parse off the beginning of the input
                    // value, to save copying it to buf in most cases.
                    consumed = parse_length(sreq.substr(0, MAX_REQ_LEN_ENCODED));
                    if (consumed == 0)
                    {
                        // The input didn't contain a number, but wasn't long enough to definitively
                        // be a number, so we copy what we have and then wait for more stream data
                        // to arrive with the rest of the number.
                        size_buf.resize(req.size());
                        std::memcpy(size_buf.data(), req.data(), req.size());
                        return;
                    }
                }
                // If we get here, then we consumed `consumed` in total and parsed it into
                // current_len, but that includes a possible `prev_len` characters we already had.
                // So remove whatever arrived in this current call from the from of req; the
                // remainder is the beginning of the incoming `current_len` request data bytes.
                assert(consumed > prev_len);
                req = req.subspan(consumed - prev_len);
            }

            assert(current_len > 0);  // We shouldn't get out of the above without knowing this

            if (auto r_size = req.size() + buf.size(); r_size >= current_len)
            {
                // We have enough data for a complete request, so copy whatever we need to
                // complete the current request into buf and process it, leaving behind the
                // potential start of the next request:
                if (buf.size() < current_len)
                {
                    size_t need = current_len - buf.size();
                    buf.insert(buf.end(), req.begin(), req.begin() + need);
                    req = req.subspan(need);
                }

                handle_input(message{*this, std::move(buf)});
                buf.clear();

                // Back to the top to try processing another request that might have arrived in
                // the same stream buffer
                current_len = 0;
                continue;
            }

            // Otherwise we don't have enough data on hand for a complete request, so move what we
            // got to the buffer to be processed when the next incoming chunk of data arrives.
            buf.reserve(current_len);
            buf.insert(buf.end(), req.begin(), req.end());
            return;
        }
    }

    std::string BTRequestStream::encode_command(std::string_view endpoint, int64_t rid, bspan body)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(message::TYPE_COMMAND);
        btlp.append(rid);
        btlp.append(endpoint);
        btlp.append(body);

        return std::move(btlp).str();
    }

    std::string BTRequestStream::encode_response(int64_t rid, bspan body, bool error)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(error ? message::TYPE_ERROR : message::TYPE_REPLY);
        btlp.append(rid);
        btlp.append(body);

        return std::move(btlp).str();
    }

    sent_request* BTRequestStream::add_sent_request(std::shared_ptr<sent_request> req)
    {
        if (is_closing())
        {
            // The stream is already dead, so fire the failure callback as a timeout right away and
            // drop the request, since we know it can never complete.  (This isn't necessarily the
            // application's fault: the closing could have started while queuing this new command
            // for the event loop).
            auto& f = *req;
            if (f.cb)
            {
                try
                {
                    f.cb(std::move(f).to_timeout());
                }
                catch (const std::exception& e)
                {
                    log::error(log_cat, "Uncaught exception from closed-stream sent request response handler: {}", e.what());
                }
            }
            return nullptr;
        }
        return sent_reqs.emplace_back(std::move(req)).get();
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
        if (pos == std::string_view::npos)
        {
            if (req.size() >= MAX_REQ_LEN_ENCODED)
                // we didn't find a valid length, but do have enough consumed for the maximum valid
                // length, so something is clearly wrong with this input.
                throw std::invalid_argument{"Invalid incoming request; invalid encoding or request too large"};

            return 0;
        }

        auto [ptr, ec] = std::from_chars(req.data(), req.data() + pos, current_len);

        const char* bad = nullptr;
        if (ec != std::errc() || ptr != req.data() + pos)
            bad = "Invalid incoming request encoding!";
        else if (current_len == 0)
            bad = "Invalid empty bt request!";
        else if (current_len > MAX_REQ_LEN)
            bad = "Request exceeds maximum size!";

        if (bad)
        {
            close(BPARSER_ERROR_EXCEPTION);
            throw std::invalid_argument{bad};
        }

        return pos + 1;
    }

    size_t BTRequestStream::num_pending() const
    {
        return call_get_accessor(&BTRequestStream::num_pending_impl);
    }

    size_t BTRequestStream::num_awaiting_response() const
    {
        return call_get_accessor(&BTRequestStream::num_awaiting_response_impl);
    }

}  // namespace oxen::quic
