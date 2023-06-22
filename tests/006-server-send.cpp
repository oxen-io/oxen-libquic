#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("006: Server successfully sending stream data", "[006][server][send]")
    {
        logger_config();

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<bool> stream_check{false};
        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_stream;

        stream_open_callback_t stream_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
            server_stream = s.shared_from_this();
            stream_check.store(true);
            return 0;
        };

        stream_data_callback_t server_stream_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
        };

        stream_data_callback_t client_stream_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling client stream data callback... data received... incrementing counter...");
            data_check += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls, stream_open_cb, server_stream_data_cb);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client = test_net.client_connect(client_local, client_remote, client_tls, client_stream_data_cb);

        std::thread client_thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            auto stream = client->open_stream();
            log::trace(log_cat, "Client sending stream message");
            stream->send(msg);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        std::thread server_thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            log::trace(log_cat, "Server sending stream message");
            server_stream->send(msg);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        REQUIRE(stream_check.load() == true);
        REQUIRE(data_check.load() == 2);
        test_net.close();

        client_thread.join();
        server_thread.join();
    };
}  // namespace oxen::quic::test
