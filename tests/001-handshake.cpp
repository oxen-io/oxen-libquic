#include "quic.hpp"

#include <catch2/catch_test_macros.hpp>


namespace oxen::quic::test
{
    using namespace std::literals;
    
    TEST_CASE("Simple client to server transmission")
    {
        fprintf(stderr, "\nBeginning test of DTLS handshake...\n");

        Network test_net{};

        client_tls_callback_t client_tls_cb = [](
            gnutls_session_t session, unsigned int htype, unsigned int when, unsigned int incoming, const gnutls_datum_t* msg) {
                fprintf(stderr, "Handshake completed...\n");

                const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
                const auto& client = static_cast<Connection*>(conn_ref->user_data)->client();

                // REQUIRE(client != nullptr);

                // async_callback_t async_cb = [&](const uvw::AsyncEvent& event, uvw::AsyncHandle &udp) {
                //     client->client_close();
                // };

                // const auto& handler = client->handler;
                // handler->client_call_async(std::move(async_cb));

                return 0;
        };

        opt::server_tls server_tls{
            "/home/dan/oxen/libquicinet/tests/serverkey.pem"s, 
            "/home/dan/oxen/libquicinet/tests/servercert.pem"s, 
            "/home/dan/oxen/libquicinet/tests/clientcert.pem"s, 
            1};

        opt::client_tls client_tls{
            0, 
            "/home/dan/oxen/libquicinet/tests/clientkey.pem"s, 
            "/home/dan/oxen/libquicinet/tests/clientcert.pem"s, 
            "/home/dan/oxen/libquicinet/tests/servercert.pem"s,
            ""s,
            client_tls_cb};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        fprintf(stderr, "Calling 'server_listen'...\n");
        auto server = test_net.server_listen(server_local, server_tls);

        fprintf(stderr, "Calling 'client_connect'...\n");
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        fprintf(stderr, "Starting event loop...\n");
        test_net.ev_loop->run();
    };
}
