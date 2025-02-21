#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("016 - stateless reset", "[016][stateless_reset]")
    {
        // TODO: currently we only test server->client stateless resets, because client->server
        // resets aren't available for the first post-handshake dcid that the server uses to talk to
        // the client (there is no means in the QUIC protocol for transmission of that stateless
        // reset token).
        //
        // It ought to work post-migration, however, and so we could conceivably test that here as
        // well.

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network net_client;
        // Unique pointer because we are going to force kill it and then start it up again for this
        // test.  We don't really have to kill the entire Network, but that's the easiest way to
        // ensure that the endpoint is completely gone.
        auto net_server = std::make_unique<Network>();

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::vector<unsigned char> secret;
        secret.resize(32);
        gnutls_rnd(GNUTLS_RND_RANDOM, secret.data(), secret.size());

        auto server_endpoint = net_server->endpoint(server_local, server_established, opt::static_secret{secret});
        server_endpoint->listen(server_tls);
        // Extract the socket we actually used (rather than the any-addr, any-port default
        // 0.0.0.0:0), because we need to be sure to re-bind to the same port when we start the
        // server again:
        server_local = server_endpoint->local();
        log::info(test_cat, "Server started with local address {}", server_local);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        uint64_t client_close_ec = 0;
        callback_waiter client_closed{[&](connection_interface& /*conn*/, uint64_t ec) { client_close_ec = ec; }};
        auto client_endpoint = net_client.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_closed);

        auto c_str = client_ci->open_stream();

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        // Kill the server by closing its socket out from under it so that it can't send any
        // graceful close packets to the client, then restart a fresh one using the same key and
        // secret that won't have any existing connection state and so should send a stateless
        // reset.
        log::info(test_cat, "Shutting down server endpoint & server");
        kill_network(net_server, server_endpoint);
        log::info(test_cat, "Initial server shutdown complete");

        REQUIRE_FALSE(client_closed.is_ready());

        // Send something down the dead path, which will make the client start sending retries on
        // the suddenly dead connection:
        c_str->send("hello"s);

        log::info(test_cat, "Starting server with wrong static secret");
        net_server = std::make_unique<Network>();

        // Flip a bit so that our static secret doesn't match:
        secret[0] ^= 1;
        server_endpoint = net_server->endpoint(server_local, opt::static_secret{secret});
        server_endpoint->listen(server_tls);
        log::info(test_cat, "Server started with local address {}", server_endpoint->local());

        // The client should get (and ignore) the stateless reset since it shouldn't match what it
        // originally received.
        bool closed = client_closed.wait(250ms);
        REQUIRE_FALSE(closed);

        log::info(test_cat, "Shutting down wrong server endpoint & server");
        server_endpoint.reset();
        net_server->set_shutdown_immediate();
        net_server.reset();
        log::info(test_cat, "Wrong server shutdown complete");

        log::info(test_cat, "Starting server with correct static secret");
        net_server = std::make_unique<Network>();

        // Flip the bit back so that we're on the correct static secret again:
        secret[0] ^= 1;
        server_endpoint = net_server->endpoint(server_local, opt::static_secret{secret});
        server_endpoint->listen(server_tls);
        log::info(test_cat, "Server started with local address {}", server_endpoint->local());

        // It shouldn't take long for the server to fire a stateless reset back at the client:
        closed = client_closed.wait(1s);
        REQUIRE(closed);
        CHECK(client_close_ec == quic::CONN_STATELESS_RESET);
    }

}  //  namespace oxen::quic::test
