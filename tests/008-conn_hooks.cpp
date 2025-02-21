#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("008 - Connection Hooks", "[008][conn][open][callbacks]")
    {
        uint64_t error_code = 12345;
        uint64_t client_error{0};
        uint64_t server_error{0};
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};
        // this needs to be destroyed *after* Network, as it may be called during ~Network
        auto client_closed = callback_waiter{[&client_error](connection_interface&, uint64_t ec) { client_error = ec; }};
        auto server_closed = callback_waiter{[&server_error](connection_interface&, uint64_t ec) { server_error = ec; }};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        SECTION("via Network::endpoint(...)")
        {
            auto server_endpoint = test_net.endpoint(server_local, server_established, server_closed);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());
            REQUIRE(server_established.wait());

            conn_interface->close_connection(error_code);
        }

        SECTION("via Endpoint::{connect,listen}(...)")
        {
            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_established, server_closed));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_established, client_closed);

            REQUIRE(client_established.wait());
            REQUIRE(server_established.wait());

            conn_interface->close_connection(error_code);
        }

        REQUIRE(server_closed.wait());
        REQUIRE(client_closed.wait());
        CHECK(client_error == error_code);
        CHECK(server_error == error_code);
    }
}  // namespace oxen::quic::test
