#include <catch2/catch_test_macros.hpp>
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

        auto server_endpoint_b = test_net.endpoint(server_a_local);
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

        auto server_endpoint_b = test_net.endpoint(server_a_local);
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
    };

}  // namespace oxen::quic::test
