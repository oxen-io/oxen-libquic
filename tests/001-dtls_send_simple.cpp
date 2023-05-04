#include "quic.hpp"

#include <catch2/catch_test_macros.hpp>


namespace oxen::quic::test
{
    using namespace std::literals;
    
    TEST_CASE("Simple client to server transmission")
    {
        fprintf(stderr, "\nBeginning test of simple client to server transmission\n");

        Network test_net{};
        auto message = "Good morning"_bsv;

        stream_data_callback_t stream_data_cb = [](Stream& s, bstring_view data) {
            fprintf(stderr, "Stream opened\n");
            auto handle = s.udp_handle;
            Packet pkt{.path = Path{handle->sock(), handle->peer()}, .data = data};
            s.conn.endpoint->handle_packet(pkt);
        };
        stream_close_callback_t stream_close_cb = [](Stream& s, uint64_t error_code) {
            s.close(error_code);
        };

        client_tls_callback_t client_tls_cb = [](
            gnutls_session_t session, 
            unsigned int htype, unsigned int when, 
            unsigned int incoming, 
            const gnutls_datum_t* msg) {
                return 0;
        };

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
        
        fprintf(stderr, "Calling 'client.open_stream'...\n");
        auto stream = client->open_stream(static_cast<uint16_t>(1500), stream_data_cb, stream_close_cb);
        fprintf(stderr, "Calling 'stream.send'...\n");
        stream->send(message, message.length());
    };
}
