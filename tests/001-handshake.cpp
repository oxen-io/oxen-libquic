#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("001 - Handshaking: Types", "[001][handshake][tls][types]")
    {
        SECTION("TLS Credentials")
        {
            REQUIRE_NOTHROW(GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s));
            REQUIRE_THROWS(GNUTLSCreds::make(""s, ""s, ""s));
        };

        SECTION("Address objects")
        {
            opt::local_addr empty_addr{};
            opt::local_addr good_addr{"127.0.0.1", 4400};

            REQUIRE(empty_addr.is_set());
            REQUIRE_THROWS(opt::local_addr{"127.001", 4400});
            REQUIRE_THROWS(opt::local_addr{""s, 0});
            REQUIRE(empty_addr == opt::local_addr{"::", 0});
            REQUIRE(good_addr.is_set());
        };

        SECTION("Endpoint object creation - Default addressing")
        {
            Network test_net{};
            opt::local_addr default_addr{};

            auto ep = test_net.endpoint(default_addr);
            // Note: kernel chooses a random port after being passed default addr
            REQUIRE_FALSE(ep->local().to_string() == default_addr.to_string());
        };

        SECTION("Endpoint::listen() - TLS credentials")
        {
            Network test_net{};
            test_net.set_shutdown_immediate();

            opt::local_addr default_addr{}, local_addr{};
            auto local_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            auto ep_notls = test_net.endpoint(default_addr);
            auto ep_tls = test_net.endpoint(local_addr);

            // ep_notls->listen();  // Shouldn't compile if uncommented!
            // ep_notls->listen(local_tls, local_tls);  // Nor this
            REQUIRE_NOTHROW(ep_tls->listen(local_tls));
        };

        SECTION("Endpoint::listen() + Endpoint::Connect() - Default addressing")
        {
            Network test_net{};
            opt::local_addr default_addr{};
            auto local_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            auto ep = test_net.endpoint(default_addr);

            REQUIRE_NOTHROW(ep->listen(local_tls));
            REQUIRE_THROWS(ep->connect(default_addr, local_tls));
        };

        SECTION("Endpoint::connect() - Immediate network shutdown")
        {
            Network test_net{};
            test_net.set_shutdown_immediate();
            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::local_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));
        };

        SECTION("Endpoint::connect() - Graceful network shutdown")
        {
            Network test_net{};
            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            // no client TLS passed
            REQUIRE_THROWS(client_endpoint->connect(client_remote));
            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));
        };
    };

    TEST_CASE("001 - Handshaking: Types - IPv6", "[001][ipv6]")
    {
        if (disable_ipv6)
            SKIP("IPv6 not enabled for this test iteration!");

        SECTION("Endpoint::connect() - IPv6 Addressing")
        {
            auto client_established = callback_waiter{[](connection_interface&) {}};
            auto server_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_established);
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"::1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

            REQUIRE(client_established.wait());
            REQUIRE(server_established.wait());
        };
    };

    TEST_CASE("001 - Handshaking: Execution", "[001][handshake][tls][execute]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(server_established.wait());
    };
}  // namespace oxen::quic::test
