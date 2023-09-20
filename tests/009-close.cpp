#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("009 - Close", "[009][close][callbacks]")
    {
        uint64_t client_error{0};
        uint64_t server_error{0};
        auto client_established = bool_waiter{[](connection_interface&) {}};
        auto server_established = bool_waiter{[](connection_interface&) {}};
        // this needs to be destroyed *after* Network, as it may be called during ~Network
        auto client_closed = bool_waiter{[&client_error](connection_interface&, uint64_t ec) { client_error = ec; }};
        auto server_closed = bool_waiter{[&server_error](connection_interface&, uint64_t ec) { server_error = ec; }};

        Network test_net{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established, server_closed);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait_ready());
        REQUIRE(server_established.wait_ready());

        uint64_t error_code = 12345;
        conn_interface->close_connection(error_code);

        REQUIRE(server_closed.get());
        REQUIRE(client_error == error_code);
        REQUIRE(client_closed.get());
        REQUIRE(server_error == error_code);
    };
}  // namespace oxen::quic::test
