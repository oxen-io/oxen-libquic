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

        std::atomic<bool> good{false};

        gnutls_callback client_tls_cb = [&](gnutls_session_t session,
                                            unsigned int htype,
                                            unsigned int when,
                                            unsigned int incoming,
                                            const gnutls_datum_t* msg) {
            log::debug(log_cat, "Calling client TLS callback... handshake completed...");

            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& client = static_cast<Connection*>(conn_ref->user_data)->client();

            REQUIRE(client != nullptr);

            good = true;
            return 0;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
        client_tls->client_tls_policy = std::move(client_tls_cb);

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls);

        log::debug(log_cat, "Calling 'client_connect'...");
        // auto client = test_net.client_connect(client_local, client_remote, client_tls, client_tls_cb);
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        REQUIRE(good);
        test_net.close();
    };
}  // namespace oxen::quic::test
