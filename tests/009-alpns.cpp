#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("009 - ALPNs", "[009][alpns][execute]")
    {
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};
        opt::handshake_timeout timeout{500ms};

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto client_established2 = callback_waiter{[](connection_interface&) {}};

        // this has to destroy *after* network, in case it doesn't go off before then
        auto client_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        Network test_net{};

        SECTION("Default ALPN")
        {
            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "default");
        }

        SECTION("No Server ALPNs specified (defaulted)")
        {
            opt::outbound_alpns client_alpns{"client"};

            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("No Client ALPNs specified (defaulted)")
        {
            opt::inbound_alpns server_alpns{"client", "relay"};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Client ALPNs not supported")
        {
            opt::inbound_alpns server_alpns{"client", "relay"};
            opt::outbound_alpns client_alpns{"foobar"};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Select first ALPN both sides support")
        {
            opt::inbound_alpns server_alpns{"client", "relay"};
            opt::outbound_alpns client_alpns{"client"};
            opt::outbound_alpns client_alpns2{"relay"};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "client");

            auto client_endpoint2 = test_net.endpoint(client_local, client_established2, client_alpns2, timeout);

            auto conn2 = client_endpoint2->connect(client_remote, client_tls);
            REQUIRE(client_established2.wait());
            REQUIRE(conn2->selected_alpn() == "relay");
        }

        SECTION("Bidirectional ALPN incoming")
        {
            opt::alpns server_alpns{"special-alpn"};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            opt::outbound_alpns client_alpns{"foobar"};
            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Bidirectional ALPN outgoing")
        {
            opt::inbound_alpns server_alpns{"special-alpn"};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            opt::alpns client_alpns{"special-alpn"};
            auto client_endpoint = test_net.endpoint(client_local, client_established, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "special-alpn");
        }
    }

}  // namespace oxen::quic::test
