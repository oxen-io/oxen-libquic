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
            opt::local_addr empty_addr2{"", 0};
            opt::local_addr good_addr{"127.0.0.1", 4400};
            opt::local_addr public_addr{"1.2.3.4", 56789};
            opt::local_addr public_anyport{"4.5.6.7", 0};
            opt::local_addr localnet_addr{"192.168.1.1", 80};
            opt::local_addr ipv6_localhost{"::1", 123};
            opt::local_addr localnet_ipv6{"fdab:1234:5::1", 123};
            opt::local_addr public_ipv6{"2345::1", 45678};

            CHECK(empty_addr.is_set());
            CHECK_THROWS(opt::local_addr{"127.001", 4400});
            CHECK_NOTHROW(opt::local_addr{"", 0});
            CHECK(empty_addr == opt::local_addr{"::", 0});
            CHECK(good_addr.is_set());

            CHECK(empty_addr.is_any_addr());
            CHECK(empty_addr.is_any_port());
            CHECK_FALSE(empty_addr.is_addressable());
            CHECK_FALSE(empty_addr.is_loopback());

            CHECK(empty_addr == empty_addr2);

            CHECK_FALSE(good_addr.is_public());
            CHECK_FALSE(good_addr.is_public_ip());
            CHECK_FALSE(good_addr.is_any_addr());
            CHECK_FALSE(good_addr.is_any_port());
            CHECK(good_addr.is_addressable());
            CHECK(good_addr.is_loopback());

            CHECK(public_addr.is_public());
            CHECK(public_addr.is_public_ip());
            CHECK_FALSE(public_addr.is_any_addr());
            CHECK_FALSE(public_addr.is_any_port());
            CHECK(public_addr.is_addressable());
            CHECK_FALSE(public_addr.is_loopback());

            CHECK_FALSE(public_anyport.is_public());
            CHECK(public_anyport.is_public_ip());
            CHECK_FALSE(public_anyport.is_any_addr());
            CHECK(public_anyport.is_any_port());
            CHECK_FALSE(public_anyport.is_addressable());
            CHECK_FALSE(public_anyport.is_loopback());

            CHECK_FALSE(localnet_addr.is_public());
            CHECK_FALSE(localnet_addr.is_public_ip());
            CHECK_FALSE(localnet_addr.is_any_addr());
            CHECK_FALSE(localnet_addr.is_any_port());
            CHECK(localnet_addr.is_addressable());
            CHECK_FALSE(localnet_addr.is_loopback());

            CHECK_FALSE(ipv6_localhost.is_public());
            CHECK_FALSE(ipv6_localhost.is_public_ip());
            CHECK_FALSE(ipv6_localhost.is_any_addr());
            CHECK_FALSE(ipv6_localhost.is_any_port());
            CHECK(ipv6_localhost.is_addressable());
            CHECK(ipv6_localhost.is_loopback());

            CHECK_FALSE(localnet_ipv6.is_public());
            CHECK_FALSE(localnet_ipv6.is_public_ip());
            CHECK_FALSE(localnet_ipv6.is_any_addr());
            CHECK_FALSE(localnet_ipv6.is_any_port());
            CHECK(localnet_ipv6.is_addressable());
            CHECK_FALSE(localnet_ipv6.is_loopback());

            CHECK(public_ipv6.is_public());
            CHECK(public_ipv6.is_public_ip());
            CHECK_FALSE(public_ipv6.is_any_addr());
            CHECK_FALSE(public_ipv6.is_any_port());
            CHECK(public_ipv6.is_addressable());
            CHECK_FALSE(public_ipv6.is_loopback());
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

            auto [local_tls, _] = defaults::tls_creds_from_ed_keys();

            auto ep_notls = test_net.endpoint(default_addr);
            auto ep_tls = test_net.endpoint(local_addr);

            REQUIRE_NOTHROW(ep_tls->listen(local_tls));
        };

        SECTION("Endpoint::listen() + Endpoint::Connect() - Default addressing")
        {
            Network test_net{};
            opt::local_addr default_addr{};
            auto [local_tls, _] = defaults::tls_creds_from_ed_keys();

            auto ep = test_net.endpoint(default_addr);

            REQUIRE_NOTHROW(ep->listen(local_tls));
            REQUIRE_THROWS(ep->connect(default_addr, local_tls));
        };

        SECTION("Endpoint::connect() - Immediate network shutdown")
        {
            Network test_net{};
            test_net.set_shutdown_immediate();

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

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

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

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

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

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

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

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
