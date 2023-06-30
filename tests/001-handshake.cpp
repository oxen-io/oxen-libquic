#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("001: Server-client handshaking", "[001][handshake]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of DTLS handshake...");
        
        Network test_net{};
        
        std::promise<bool> tls;
        std::future<bool> tls_future = tls.get_future();

        gnutls_callback outbound_tls_cb = [&](gnutls_session_t,
                                              unsigned int,
                                              unsigned int,
                                              unsigned int,
                                              const gnutls_datum_t*) {
            log::debug(log_cat, "Calling client TLS callback... handshake completed...");

            tls.set_value(true);
            return 0;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
        client_tls->set_client_tls_policy(outbound_tls_cb);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(tls_future.get());
        test_net.close();
    };
}  // namespace oxen::quic::test
