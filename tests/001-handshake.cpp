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
            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();
            REQUIRE_NOTHROW(GNUTLSCreds::make_from_ed_keys(defaults::CLIENT_SEED, defaults::CLIENT_PUBKEY));
            REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(""s, ""s));
        };

        SECTION("Address objects")
        {
            Address empty_addr{};
            Address empty_addr2{"", 0};
            Address good_addr{"127.0.0.1", 4400};
            Address public_addr{"1.2.3.4", 56789};
            Address public_anyport{"4.5.6.7", 0};
            Address localnet_addr{"192.168.1.1", 80};
            Address ipv6_localhost{"::1", 123};
            Address localnet_ipv6{"fdab:1234:5::1", 123};
            Address public_ipv6{"2345::1", 45678};

            CHECK(empty_addr.is_set());
            CHECK_THROWS(Address{"127.001", 4400});
            CHECK_NOTHROW(Address{"", 0});
            CHECK(empty_addr == Address{"::", 0});
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
            Address default_addr{};

            auto ep = test_net.endpoint(default_addr);
            // Note: kernel chooses a random port after being passed default addr
            CHECK_FALSE(ep->local().to_string() == default_addr.to_string());
        };

        SECTION("Endpoint::listen() - TLS credentials")
        {
            Network test_net{};
            test_net.set_shutdown_immediate();

            Address default_addr{}, local_addr{};

            auto [local_tls, _] = defaults::tls_creds_from_ed_keys();

            auto ep_notls = test_net.endpoint(default_addr);
            auto ep_tls = test_net.endpoint(local_addr);

            CHECK_NOTHROW(ep_tls->listen(local_tls));
        };
    };

    TEST_CASE("001 - Handshaking: Client Validation", "[001][client]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        SECTION("Pubkey failures")
        {
            SECTION("Incorrect pubkey in remote")
            {
                uint64_t client_error{0}, client_attempt{0};

                auto client_established_2 =
                        callback_waiter{[&client_attempt](connection_interface&) { client_attempt = 1000; }};

                auto client_closed =
                        callback_waiter{[&client_error](connection_interface&, uint64_t) { client_error = 1000; }};
                RemoteAddress client_remote{defaults::CLIENT_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

                auto client_endpoint = test_net.endpoint(client_local, client_established_2, client_closed);

                CHECK_THROWS(client_endpoint->connect(client_remote));

                auto client_ci = client_endpoint->connect(client_remote, client_tls);

                CHECK(not client_established_2.wait());
                CHECK(client_attempt != 1000);
                CHECK(client_error == 1000);
            };

            SECTION("No pubkey in remote")
            {
                // If uncommented, this line will not compile! Remote addresses must pass a remote pubkey to be
                // verified upon the client successfully establishing connection with a remote.

                // RemoteAddress client_remote{"127.0.0.1"s, server_endpoint->local().port()};
                CHECK(true);
            };
        }

        SECTION("Pubkey successes")
        {
            auto client_endpoint = test_net.endpoint(client_local, client_established);

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            SECTION("Correct pubkey in remote")
            {
                auto client_ci = client_endpoint->connect(client_remote, client_tls);

                // This will return false until the connection has had time to establish and validate. Depending
                // on the architecture running the test, the connection may be already established and validated
                // by the time this line es executed
                CHECK_NOFAIL(client_ci->is_validated());

                CHECK(client_established.wait());
                CHECK(server_established.wait());
                CHECK(client_ci->is_validated());
            };

            SECTION("Immediate network shutdown after calling connect")
            {
                test_net.set_shutdown_immediate();

                CHECK_NOTHROW(client_endpoint->connect(client_remote, client_tls));
            };
        }
    };

    TEST_CASE("001 - Handshaking: Server Validation", "[001][server]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        CHECK(client_ci->is_validated());
        CHECK(server_ci->is_validated());
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

            Address server_local{};
            Address client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_established);
            CHECK_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "::1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);

            CHECK_NOTHROW(client_endpoint->connect(client_remote, client_tls));
            CHECK(client_established.wait());
            CHECK(server_established.wait());
        };
    };

    TEST_CASE("001 - Handshaking: Execution", "[001][handshake][tls][execute]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());
        CHECK(client_ci->is_validated());
    };
}  // namespace oxen::quic::test
