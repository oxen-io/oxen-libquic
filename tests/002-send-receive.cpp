#include "quic.hpp"

#include <catch2/catch_test_macros.hpp>


namespace oxen::quic::test
{
    using namespace std::literals;

    /*  TODO:
        - pass server data cb into server_listen call
        - create method "call_async"
    */
    
    TEST_CASE("Simple client to server transmission")
    {
        fprintf(stderr, "\nBeginning test of send/receive...\n");

        Network test_net{};
        auto message = "Good morning"_bsv;

        server_data_callback_t server_data_cb = [msg = reinterpret_cast<const char*>(message.data())](
            const uvw::UDPDataEvent& event, uvw::UDPHandle& udp) {
                auto incoming = std::basic_string_view{event.data.get()};
                auto outgoing = std::basic_string_view{msg};

                REQUIRE(incoming.data() == outgoing.data());
                REQUIRE(incoming.length() == outgoing.length());
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
            nullptr};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        fprintf(stderr, "Calling 'server_listen'...\n");
        auto server = test_net.server_listen(server_local, server_tls);
        fprintf(stderr, "Calling 'client_connect'...\n");
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        fprintf(stderr, "Starting event loop...\n");
        test_net.ev_loop->run();
        
        // fprintf(stderr, "\n\n\n\n\nCalling 'client.open_stream'...\n");
        // auto stream = client->open_stream(static_cast<uint16_t>(1500), stream_data_cb, stream_close_cb);
        // fprintf(stderr, "Calling 'stream.send'...\n");
        // stream->send(message, message.length());
    };
}
