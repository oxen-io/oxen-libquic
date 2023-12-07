#include <catch2/catch_test_macros.hpp>
#include <future>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][execute]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        REQUIRE(d_future.get());
    };

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][bidirectional]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::vector<std::promise<bool>> d_promises{2};
        std::vector<std::future<bool>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value(true);
            index += 1;
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};
        Address client_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_b->local().port()};
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_a->local().port()};

        auto server_ci = server_endpoint_b->connect(server_remote, server_tls);
        auto server_stream = server_ci->get_new_stream();

        server_stream->send(good_msg);

        REQUIRE(d_futures[0].get());

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        REQUIRE(d_futures[1].get());
    };

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][2x2]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::vector<std::promise<bool>> d_promises{2};
        std::vector<std::future<bool>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value(true);
            index += 1;
        };

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_b->local().port()};

        auto server_a_ci = server_endpoint_b->connect(server_remote_a, server_tls);
        auto server_a_stream = server_a_ci->get_new_stream();

        server_a_stream->send(good_msg);

        REQUIRE(d_futures[0].get());

        auto server_b_ci = server_endpoint_a->connect(server_remote_b, server_tls);

        auto server_b_stream = server_b_ci->get_new_stream();

        server_b_stream->send(good_msg);

        REQUIRE(d_futures[1].get());
    };

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
            log::debug(log_cat, "Server stream data callback -- data received (len {})", dat.size());
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

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint_b->local().port()};

        auto conn_to_a = server_endpoint_b->connect(server_remote_a, server_tls);
        auto stream_to_a = conn_to_a->get_new_stream();

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

        auto wait_result = done_receiving.get_future().wait_for(5s);
        REQUIRE(wait_result == std::future_status::ready);
        {
            std::lock_guard lock{received_mut};
            CHECK(good == tests);
            CHECK(bad == 0);
        }
    };

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
                    log::info(log_cat, "Server bparser received: {}", msg.view());
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = std::make_shared<BTRequestStream>(c, e);
                s->register_command("test_endpoint"s, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->get_new_stream<BTRequestStream>();

            client_bp->command("test_endpoint"s, "test_request_body"s);

            REQUIRE(server_bp_cb.wait());
        }

        SECTION("Client sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(log_cat, "Server bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(log_cat, "Client bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = std::make_shared<BTRequestStream>(c, e);
                s->register_command("test_endpoint"s, server_bp_cb);
                return s;
            };

            stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                return std::make_shared<BTRequestStream>(c, e);
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

            std::shared_ptr<BTRequestStream> client_bp = conn_interface->get_new_stream<BTRequestStream>();

            client_bp->command("test_endpoint"s, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
        }

        SECTION("Client (alternate construction) sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(log_cat, "Server bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(log_cat, "Client bparser received: {}", msg.view());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = std::make_shared<BTRequestStream>(c, e);
                s->register_command("test_endpoint"s, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->get_new_stream<BTRequestStream>();

            client_bp->command("test_endpoint"s, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
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
                log::info(log_cat, "Server bparser received: {}", msg.view());
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
                log::debug(log_cat, "Client bparser received response {}: {}", responses, msg.view());
                if (msg.body() == res_msg)
                    good_responses++;
                if (responses == num_requests)
                    done_prom.set_value();
            }
            else
            {
                log::debug(log_cat, "got back a failed message response");
            }
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            auto s = std::make_shared<BTRequestStream>(c, e);
            s->register_command("test_endpoint"s, server_handler);
            return s;
        };

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->get_new_stream<BTRequestStream>();

        for (int i = 0; i < num_requests; i++)
        {
            client_bp->command("test_endpoint"s, req_msg, client_reply_handler);
        }

        CHECK(done.wait_for(5s) == std::future_status::ready);
        std::lock_guard lock{mut};
        CHECK(good_responses == num_requests);
        CHECK(responses == good_responses);
    }

}  // namespace oxen::quic::test
