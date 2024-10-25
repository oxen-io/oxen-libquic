#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    static constexpr auto _a = "apple pie"sv;
    static constexpr auto _b = "tell me a good story"sv;
    static constexpr auto _c = 476938;
    static constexpr auto _n = "good night"sv;

    static bool bt_decode(std::string_view arg)
    {
        auto ret = true;

        try
        {
            oxenc::bt_dict_consumer btdc{arg};
            ret &= btdc.require<std::string_view>("a") == _a;
            ret &= btdc.require<std::string_view>("b") == _b;
            ret &= btdc.require<int>("c") == _c;
            ret &= btdc.require<std::string_view>("n") == _n;
        }
        catch (const std::exception& e)
        {
            log::warning(test_cat, "BT decode exception: {}", e.what());
            ret = false;
        }

        return ret;
    }

    static std::string bt_encode()
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("a", _a);
        btdp.append("b", _b);
        btdp.append("c", _c);
        btdp.append("n", _n);

        return std::move(btdp).str();
    }

    TEST_CASE("015 - Bt-encoding; Messaging", "[015][bt][messaging]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_bp_cb = callback_waiter{[&](message msg) {
            log::debug(test_cat, "Server bparser received: {}", msg.view());
            CHECK(bt_decode(msg.body()));
            msg.respond(msg.body());
        }};

        auto client_bp_cb = callback_waiter{[&](message msg) {
            log::debug(test_cat, "Client bparser received: {}", msg.view());
            CHECK(bt_decode(msg.body()));
        }};

        auto server_conn_established = [&](connection_interface& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler(TEST_ENDPOINT, server_bp_cb);
        };

        stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            return e.make_shared<BTRequestStream>(c, e);
        };

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_conn_established));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

        client_bp->command(TEST_ENDPOINT, bt_encode(), client_bp_cb);

        REQUIRE(server_bp_cb.wait());
        REQUIRE(client_bp_cb.wait());
    }

    TEST_CASE("015 - Bt-encoding; Message Chaining", "[015][bt][chaining]")
    {
        // clang-format off
        /** 
                Node A              Node B              Node C
                req(A)      ->      recv(A)                         1) Node A dispatches req-A to Node B
                                    chain(B)    ->      recv(B)     2) Node B chains req-B to Node C; Node C receives req-B from Node B
                recv(C)     <-          <-      <-      chain(C)    3) Node C chains req-C to Node A; Node A receives req-A from Node C
                reply(C)    ->          ->      ->      recv(C)     4) Node A replies to req-C; Node C receives req-C reply from Node A
                                    recv(B)     <-      reply(B)    5) Node C replies to req-B; Node B receives req-B reply from Node B
                recv(A)     <-      reply(A)                        6) Node B replies to req-A; Node A receives req-A reply from Node B
        */
        // clang-format on

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address node_a_local{};
        Address node_b_local{};
        Address node_c_local{};

        std::shared_ptr<BTRequestStream> node_a_bp, node_b_bp, node_c_bp;

        auto node_a_response_cb = callback_waiter{[&](message msg) {
            log::debug(test_cat, "Node A received response from Node B: {}", msg.view());
            CHECK(bt_decode(msg.body()));
        }};

        auto node_a_bp_cb = [&](message msg) {
            log::debug(test_cat, "Node A received request from Node C: {}", msg.view());
            CHECK(bt_decode(msg.body()));
            msg.respond(msg.body());
        };

        auto node_b_bp_cb = [&](message msg) {
            log::debug(test_cat, "Node B received request from Node A: {}", msg.view());
            CHECK(bt_decode(msg.body()));

            log::debug(test_cat, "Node B chaining request to Node C", msg.view());
            auto body = msg.body_str();
            node_b_bp->command(TEST_ENDPOINT, std::move(body), [prev = std::move(msg)](message msg) mutable {
                log::debug(test_cat, "Node B received response from Node C: {}", msg.view());
                prev.respond(msg.body());
            });
        };

        auto node_c_bp_cb = [&](message msg) {
            log::debug(test_cat, "Node C received request from Node B: {}", msg.view());
            CHECK(bt_decode(msg.body()));

            log::debug(test_cat, "Node C chaining request to Node A", msg.view());
            auto body = msg.body_str();
            node_c_bp->command(TEST_ENDPOINT, std::move(body), [prev = std::move(msg)](message msg) mutable {
                log::debug(test_cat, "Node C received response from Node A: {}", msg.view());
                prev.respond(msg.body());
            });
        };

        auto inbound_conn_established_a = [&](connection_interface& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler(TEST_ENDPOINT, node_a_bp_cb);
        };

        auto inbound_conn_established_b = [&](connection_interface& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler(TEST_ENDPOINT, node_b_bp_cb);
        };

        auto inbound_conn_established_c = [&](connection_interface& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler(TEST_ENDPOINT, node_c_bp_cb);
        };

        stream_constructor_callback outbound_stream_ctor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            return e.make_shared<BTRequestStream>(c, e);
        };

        auto node_a = test_net.endpoint(node_a_local);
        auto node_b = test_net.endpoint(node_b_local);
        auto node_c = test_net.endpoint(node_c_local);

        REQUIRE_NOTHROW(node_a->listen(server_tls, inbound_conn_established_a));
        REQUIRE_NOTHROW(node_b->listen(server_tls, inbound_conn_established_b));
        REQUIRE_NOTHROW(node_c->listen(server_tls, inbound_conn_established_c));

        RemoteAddress node_a_remote{defaults::SERVER_PUBKEY, LOCALHOST, node_b->local().port()};
        RemoteAddress node_b_remote{defaults::SERVER_PUBKEY, LOCALHOST, node_c->local().port()};
        RemoteAddress node_c_remote{defaults::SERVER_PUBKEY, LOCALHOST, node_a->local().port()};

        auto node_a_ci = node_a->connect(node_a_remote, client_tls, outbound_stream_ctor);
        auto node_b_ci = node_b->connect(node_b_remote, client_tls, outbound_stream_ctor);
        auto node_c_ci = node_c->connect(node_c_remote, client_tls, outbound_stream_ctor);

        node_a_bp = node_a_ci->open_stream<BTRequestStream>();
        node_b_bp = node_b_ci->open_stream<BTRequestStream>();
        node_c_bp = node_c_ci->open_stream<BTRequestStream>();

        node_a_bp->command(TEST_ENDPOINT, bt_encode(), node_a_response_cb);

        REQUIRE(node_a_response_cb.wait());
    }
}  //  namespace oxen::quic::test
