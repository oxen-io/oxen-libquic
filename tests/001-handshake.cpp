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

            REQUIRE_THROWS(opt::local_addr{"127.001", 4400});
            REQUIRE_THROWS(opt::local_addr{""s, 0});
            REQUIRE(empty_addr.is_set());
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

            REQUIRE_THROWS(ep_notls->listen());
            REQUIRE_NOTHROW(ep_tls->listen(local_tls));
        };

        SECTION("Endpoint::listen() - Default addressing")
        {
            Network test_net{};
            opt::local_addr default_addr{};
            auto local_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            auto ep = test_net.endpoint(default_addr);

            REQUIRE_NOTHROW(ep->listen(local_tls));
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
            bool_waiter<connection_established_callback> server_established;
            bool_waiter<connection_established_callback> client_established;
            Network test_net{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_established.func());
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"::1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established.func());

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

            REQUIRE(client_established.wait_ready());
            REQUIRE(server_established.is_ready());
            REQUIRE(server_established.get() == true);
            REQUIRE(client_established.get() == true);
        };
    };

    TEST_CASE("001 - Handshaking: Execution", "[001][handshake][tls][execute]")
    {
        SECTION("Unsuccessful TLS handshake - No server TLS credentials")
        {
            std::atomic<bool> success = false;
            connection_established_callback established_cb = [&success](auto&&...) { success = true; };
            bool_waiter<connection_closed_callback> server_closed;
            Network test_net{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local, established_cb);
            REQUIRE_THROWS(server_endpoint->listen());

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, server_closed.func(), established_cb);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(server_closed.wait_ready(10s));  // handshake timeout is 5s, give it some leeway
            REQUIRE(success == false);
        };

        SECTION("Successful TLS handshake")
        {
            bool_waiter<connection_established_callback> server_established;
            bool_waiter<connection_established_callback> client_established;
            Network test_net{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_established.func());
            REQUIRE(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established.func());
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());
            REQUIRE(server_established.is_ready());
            REQUIRE(server_established.get() == true);
            REQUIRE(client_established.get() == true);
        };
    };
}  // namespace oxen::quic::test
