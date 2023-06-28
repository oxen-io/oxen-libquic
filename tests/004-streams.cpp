#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("004: Multiple pending streams; user config", "[004][streams][pending][config]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of client to server transmission...");

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<bool> good{false};
        std::atomic<int> data_check{0};

        opt::max_streams max_streams{8};

        stream_data_callback_t server_stream_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto server_endpoint = test_net.endpoint(server_local);
        bool sinit = server_endpoint->listen(server_tls, max_streams, server_stream_data_cb);

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        std::this_thread::sleep_for(100ms);

        std::vector<std::shared_ptr<Stream>> streams{12};

        for (auto& s : streams)
            s = conn_interface->get_new_stream();

        for (auto& s : streams)
            s->send(msg);

        std::this_thread::sleep_for(100ms);

        streams[0]->close();
        streams[1]->close();

        std::this_thread::sleep_for(100ms);

        streams[2]->close();
        streams[3]->close();

        std::this_thread::sleep_for(100ms);

        streams[4]->close();

        std::this_thread::sleep_for(100ms);

        streams[0] = conn_interface->get_new_stream();
        streams[1] = conn_interface->get_new_stream();

        std::this_thread::sleep_for(100ms);

        auto conn = client_endpoint->get_conn_ptr(conn_interface->scid());

        REQUIRE(conn->num_pending() == 1);
        REQUIRE(data_check == 12);

        test_net.close();
    };
}  // namespace oxen::quic::test
