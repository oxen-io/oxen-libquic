#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("014 - 0rtt", "[014][0rtt]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established, opt::enable_0rtt_ticketing{});
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established, opt::enable_0rtt_ticketing{});
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());
        CHECK(client_ci->is_validated());
    }

    TEST_CASE("069 - stateless reset", "[069][reset]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established, opt::disable_stateless_reset{});
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established, opt::disable_stateless_reset{});
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());
        CHECK(client_ci->is_validated());
    }
}  //  namespace oxen::quic::test
