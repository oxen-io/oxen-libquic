#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "quic.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("004: Multiple pending streams", "[004][streams]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of client to server transmission...");

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<bool> good{false};

        server_data_callback_t server_data_cb = [&](const uvw::UDPDataEvent& event, uvw::UDPHandle& udp) {
            log::debug(log_cat, "Calling server data callback... data received...");
            good = true;
        };

        opt::server_tls server_tls{"./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s};

        opt::client_tls client_tls{"./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls, server_data_cb);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        std::vector<std::shared_ptr<Stream>> streams{36};

        for (auto& s : streams)
            s = client->open_stream();

        for (auto& s : streams)
            s->send(msg);

        std::thread ev_thread{[&]() { test_net.run(); }};

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        streams[0]->close();
        streams[1]->close();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        streams[2]->close();
        streams[3]->close();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        streams[4]->close();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        streams[0] = client->open_stream();
        streams[1] = client->open_stream();

        REQUIRE(good == true);
        auto conn = client->get_conn(client->context->conn_id);
        REQUIRE(conn->pending_streams.size() == 1);
        test_net.close();

        test_net.ev_loop->close();
        ev_thread.detach();
    };
}  // namespace oxen::quic::test
