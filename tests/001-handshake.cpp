#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    bool run{true};
    bool good{false};

    void signal_handler(int)
    {
        run = false;
    }

    TEST_CASE("Simple client to server transmission")
    {
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        logger_config();

        log::debug(log_cat, "Beginning test of DTLS handshake...");

        Network test_net{};

        client_tls_callback_t client_tls_cb = [&](gnutls_session_t session,
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

        opt::server_tls server_tls{
                "/home/dan/oxen/libquicinet/tests/certs/serverkey.pem"s,
                "/home/dan/oxen/libquicinet/tests/certs/servercert.pem"s,
                "/home/dan/oxen/libquicinet/tests/certs/clientcert.pem"s};

        opt::client_tls client_tls{
                "/home/dan/oxen/libquicinet/tests/certs/clientkey.pem"s,
                "/home/dan/oxen/libquicinet/tests/certs/clientcert.pem"s,
                "/home/dan/oxen/libquicinet/tests/certs/servercert.pem"s};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client = test_net.client_connect(client_local, client_remote, client_tls, client_tls_cb);

        std::thread ev_thread{[&]() { test_net.run(); }};

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        std::thread async_thread([&]() {
            REQUIRE(good == true);
            test_net.close();
        });

        test_net.ev_loop->close();
        async_thread.join();
        ev_thread.detach();
    };
}  // namespace oxen::quic::test
