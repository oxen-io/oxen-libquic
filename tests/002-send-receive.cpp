#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][execute]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        require_future(d_future);
    }

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][bidirectional]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::vector<std::promise<void>> d_promises{2};
        std::vector<std::future<void>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value();
            index += 1;
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};
        Address client_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};

        auto server_ci = server_endpoint_b->connect(server_remote, server_tls);
        auto server_stream = server_ci->open_stream();

        server_stream->send(good_msg);

        require_future(d_futures[0]);

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        require_future(d_futures[1]);
    }

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][2x2]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::vector<std::promise<void>> d_promises{2};
        std::vector<std::future<void>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value();
            index += 1;
        };

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};

        auto server_b_ci = server_endpoint_b->connect(server_remote_a, server_tls);
        auto server_b_stream = server_b_ci->open_stream();

        server_b_stream->send(good_msg);

        require_future(d_futures[0]);

        auto server_a_ci = server_endpoint_a->connect(server_remote_b, server_tls);

        auto server_a_stream = server_a_ci->open_stream();

        server_a_stream->send(good_msg);

        require_future(d_futures[1]);
    }

    TEST_CASE("002 - Client to server transmission, larger string ownership", "[002][simple][larger][ownership]")
    {
        Network test_net{};
        bstring good_msg;
        good_msg.reserve(2600);
        for (int i = 0; i < 100; i++)
            for (char c = 'a'; c <= 'z'; c++)
                good_msg.push_back(static_cast<std::byte>(c));

        constexpr int tests = 10;
        std::mutex received_mut;
        int good = 0, bad = 0;
        std::promise<void> done_receiving;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(test_cat, "Server stream data callback -- data received (len {})", dat.size());
            static bstring partial;
            partial.append(dat);
            if (partial.size() < good_msg.size())
                return;
            std::lock_guard lock{received_mut};
            if (bstring_view{partial}.substr(0, good_msg.size()) == good_msg)
                good++;
            else
                bad++;
            partial = partial.substr(good_msg.size());
            if (good + bad >= tests)
                done_receiving.set_value();
        };

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};

        auto conn_to_a = server_endpoint_b->connect(server_remote_a, server_tls);
        auto stream_to_a = conn_to_a->open_stream();

        SECTION("Sending bstring_view of long-lived buffer")
        {
            for (int i = 0; i < tests; i++)
            {
                // There is no ownership issue here: we're just viewing into our `good_msg` which we
                // are keeping alive already for the duration of this test.
                stream_to_a->send(bstring_view{good_msg});
            }
        }
        SECTION("Sending bstring buffer with transferred ownership")
        {
            for (int i = 0; i < tests; i++)
            {
                // Deliberately construct a new temporary string here, and move it into `send()` to
                // transfer ownership of it off to the stream to manage:
                bstring copy{good_msg};
                stream_to_a->send(std::move(copy));
            }
        }
        SECTION("Sending bstring_view buffer with managed keep-alive")
        {
            for (int i = 0; i < tests; i++)
            {
                // Similar to the above, but keep the data alive via a manual shared_ptr keep-alive
                // object.
                auto ptr = std::make_shared<bstring>(good_msg);
                stream_to_a->send(bstring_view{*ptr}, ptr);
            }
        }

        require_future(done_receiving.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            CHECK(good == tests);
            CHECK(bad == 0);
        }
    }

    TEST_CASE("002 - BParser Testing", "[002][bparser]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        SECTION("Client sends a command")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                    log::info(test_cat, "Server bparser received: {}", msg.view());
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s);

            REQUIRE(server_bp_cb.wait());
        }

        SECTION("Client sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Server bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Client bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                return e.make_shared<BTRequestStream>(c, e);
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

            std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
        }

        SECTION("Client (alternate construction) sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Server bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Client bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
        }

        SECTION("Timeouts and errors")
        {
            auto server_bp_cb = [&](message m) {
                if (m.body() == "hello")
                    m.respond("goodbye");
                else if (m.body() == "I need a reply crypto-soon")
                {
                }  // <-- Crypto-soon, defined.
                else if (m.body() == "I hate you")
                    m.respond("lol", true);
            };

            int saw_regular = 0, saw_timeout = 0, saw_error = 0;

            std::promise<void> done;

            auto client_bp_cb = [&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "GOT REGULAR");
                    saw_regular++;
                }
                else if (msg.is_error())
                {
                    log::info(test_cat, "GOT ERROR");

                    saw_error++;
                }
                else if (msg.timed_out)
                {
                    log::info(test_cat, "GOT TIMEOUT");
                    saw_timeout++;
                }

                if (saw_regular + saw_error + saw_timeout >= 3)
                    done.set_value();
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler("test"s, server_bp_cb);
                return s;
            };

            stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                return e.make_shared<BTRequestStream>(c, e);
            };

            auto server_endpoint = test_net.endpoint(server_local);
            server_endpoint->listen(server_tls, server_constructor);

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command("test"s, "hello"s, client_bp_cb);
            client_bp->command("test"s, "I need a reply crypto-soon"s, client_bp_cb, 250ms);
            client_bp->command("test"s, "I hate you"s, client_bp_cb);

            auto fut = done.get_future();
            require_future(fut);

            CHECK(saw_regular == 1);
            CHECK(saw_timeout == 1);
            CHECK(saw_error == 1);
        }
    }

    TEST_CASE("002 - BParser multi-request testing", "[002][bparser][multi]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        static constexpr int num_requests = 50;

        std::mutex mut;
        std::promise<void> done_prom;
        auto done = done_prom.get_future();
        int responses = 0, good_responses = 0;

        constexpr auto req_msg = "you will never get this, you will never get this, la la la la la"sv;
        constexpr auto res_msg = "he break a cage and he get this"sv;

        auto server_handler = [&](message msg) {
            if (msg)
            {
                log::info(test_cat, "Server bparser received: {}", msg.view());
                if (msg.body() == req_msg)
                    msg.respond(res_msg);
                else
                    msg.respond("that would not be funny in America");
            }
        };

        auto client_reply_handler = [&](message msg) {
            if (msg)
            {
                std::lock_guard lock{mut};
                responses++;
                log::debug(test_cat, "Client bparser received response {}: {}", responses, msg.view());
                if (msg.body() == res_msg)
                    good_responses++;
                if (responses == num_requests)
                    done_prom.set_value();
            }
            else
            {
                log::debug(test_cat, "got back a failed message response");
            }
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            auto s = e.make_shared<BTRequestStream>(c, e);
            s->register_handler(TEST_ENDPOINT, server_handler);
            return s;
        };

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

        for (int i = 0; i < num_requests; i++)
        {
            client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler);
        }

        require_future(done);
        std::lock_guard lock{mut};
        CHECK(good_responses == num_requests);
        CHECK(responses == good_responses);
    }

    TEST_CASE("002 - BParser huge requests", "[002][bparser][huge]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        static constexpr int num_requests = 2;

        // Make sure debug logging is off for these because at debug log this produces so much log
        // output it can take too long to run the tests within our 5s future wait.
        log_level_raiser log_relief{log::Level::info};

        SECTION("Huge but not too huge")
        {
            std::promise<void> done_prom;
            auto done = done_prom.get_future();

            std::atomic<int> responses = 0, good_responses = 0;

            std::string req_msg(9'000'000, 'a');
            constexpr auto res_msg = "oh look some a's"sv;

            auto server_handler = [&](message msg) mutable {
                if (msg)
                {
                    if (msg.body() == req_msg)
                        msg.respond(res_msg);
                    else
                        msg.respond("where are all the a's?!");
                }
            };

            auto client_reply_handler = [&](message msg) mutable {
                if (msg)
                {
                    ++responses;
                    log::debug(test_cat, "Client bparser received response {}: {}", responses.load(), msg.view());
                    if (msg.body() == res_msg)
                        ++good_responses;
                    if (responses == num_requests)
                        done_prom.set_value();
                }
                else
                {
                    log::debug(test_cat, "got back a failed message response");
                }
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_handler);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

            for (int i = 0; i < num_requests; i++)
            {
                client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler);
            }

            require_future(done, 10s);
            CHECK(good_responses == num_requests);
            CHECK(responses == good_responses);
        }

        SECTION("Too huge")
        {
            std::string req_msg(10'000'000, 'a');

            auto server_handler = [&](message) mutable {
                REQUIRE(false);  // Should not get here!
            };

            auto client_reply_handler = [&](message msg) mutable {
                if (msg)
                    log::debug(test_cat, "Client bparser received response: {}", msg.view());
                else
                    log::debug(test_cat, "got back a failed message response");
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_handler);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            SECTION("Send failure")
            {
                std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();
                CHECK_THROWS_WITH(
                        client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler), "Request body too long!");
            }

            SECTION("Receive failure")
            {
                // Construct a bt request manually so that we can send invalid (too long) data at the
                // server (normally a client won't let us do that, as tested in the above section)
                std::string payload = "li123e1:C{}:{}e"_format(req_msg.size(), req_msg);
                payload = "{}:{}"_format(payload.size(), payload);

                std::atomic<uint64_t> close_err = -1;
                auto stream_close_cb = callback_waiter{[&](Stream&, uint64_t error_code) { close_err = error_code; }};
                auto str = conn_interface->open_stream<Stream>(nullptr, stream_close_cb);

                str->send(std::move(payload));

                REQUIRE(stream_close_cb.wait());
                CHECK(close_err.load() == BPARSER_ERROR_EXCEPTION);
            }
        }
    }

    TEST_CASE("002 - BParser generic request handler", "[002][bparser][generic]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::promise<void> prom;
        auto done = prom.get_future();

        auto handler1 = [&](message m) { m.respond("h1-{}"_format(m.endpoint())); };

        auto handler2 = [&](message) { throw no_such_endpoint{}; };

        auto handler_generic = [&](message m) {
            if (m.endpoint() == "nuh uh")
                throw no_such_endpoint{};
            m.respond("hg-{}"_format(m.endpoint()));
        };

        std::function<void(connection_interface&)> server_conn_est;
        SECTION("generic handler via constructor")
        {
            server_conn_est = [&](connection_interface& c) {
                auto s = c.queue_incoming_stream<BTRequestStream>(std::move(handler_generic));
                s->register_handler("ep1"s, handler1);
                s->register_handler("ep2"s, handler2);
            };
        }
        SECTION("generic handler via method")
        {
            server_conn_est = [&](connection_interface& c) {
                auto s = c.queue_incoming_stream<BTRequestStream>();
                s->register_handler("ep1"s, handler1);
                s->register_handler("ep2"s, handler2);
                s->register_generic_handler(std::move(handler_generic));
            };
        }

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_conn_est);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::unordered_multiset<std::string> responses, errors;
        auto resp_handler = [&](message m) {
            if (m)
                responses.insert(m.body_str());
            else
                errors.insert(m.body_str());
            if (responses.size() + errors.size() >= 4)
                prom.set_value();
        };

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();
        client_bp->command("ep1", "", resp_handler);
        client_bp->command("ep2", "", resp_handler);
        client_bp->command("ep3", "", resp_handler);
        client_bp->command("nuh uh", "", resp_handler);

        require_future(done);
        CHECK(responses == std::unordered_multiset{{"h1-ep1"s, "hg-ep3"s}});
        CHECK(errors == std::unordered_multiset{{"Invalid endpoint 'nuh uh'"s, "Invalid endpoint 'ep2'"s}});
    }

    TEST_CASE("002 - BParser connection close triggers timeout callback", "[002][bparser][close]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::thread slow_response;
        auto server_conn_est = [&](connection_interface& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler("sleep"s, [&](message m) {
                slow_response = std::thread{[m = std::move(m)] {
                    std::this_thread::sleep_for(1s);
                    m.respond("I'm slow");
                }};
            });
        };

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_conn_est);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, opt::idle_timeout{50ms});

        auto client_bp = conn_interface->open_stream<BTRequestStream>();

        bool got_timeout = false;
        callback_waiter reply_handler{[&](message response) { got_timeout = response.timed_out; }};
        client_bp->command("sleep"s, ""s, reply_handler);

        REQUIRE(reply_handler.wait());
        CHECK(got_timeout);

        if (slow_response.joinable())
            slow_response.join();
    }
}  // namespace oxen::quic::test
