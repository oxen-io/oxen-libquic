#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("010 - ALPNs", "[010][alpns][execute]")
    {
        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};
        opt::handshake_timeout timeout{500ms};

        auto client_established = callback_waiter{[](connection_interface&) {}};

        // this has to destroy *after* network, in case it doesn't go off before then
        auto client_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        Network test_net{};

        SECTION("No ALPNs specified")
        {
            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "default"sv);
        };

        SECTION("No Server ALPNs specified")
        {
            opt::outbound_alpns client_alpns{.alpns{"client"}};

            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        };

        SECTION("No Client ALPNs specified")
        {
            opt::inbound_alpns server_alpns{.alpns{"client", "relay"}};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        };

        SECTION("Client ALPNs not supported")
        {
            opt::inbound_alpns server_alpns{.alpns{"client", "relay"}};
            opt::outbound_alpns client_alpns{.alpns{"foobar"}};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        };

        SECTION("Select first ALPN both sides support")
        {
            opt::inbound_alpns server_alpns{.alpns{"client", "relay"}};
            opt::outbound_alpns client_alpns{.alpns{"client"}};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "client"sv);
        };
    };

}  // namespace oxen::quic::test
