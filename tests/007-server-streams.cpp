#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("007: Server creating streams", "[007][server][streams][TOPSECRET]")
    {
        logger_config();

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;
        auto response = "okay okay i get it already"_bsv;

        std::atomic<int> stream_check{0};
        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_extracted_stream, client_extracted_stream;
        std::shared_ptr<connection_interface> server_ci;

        stream_open_callback_t server_stream_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
            server_extracted_stream = s.shared_from_this();
            stream_check += 1;
            return 0;
        };

        stream_open_callback_t client_stream_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling client stream open callback... stream opened...");
            client_extracted_stream = s.shared_from_this();
            stream_check += 1;
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

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto server_endpoint = test_net.endpoint(server_local);
        bool sinit = server_endpoint->listen(server_tls, server_stream_data_cb, server_stream_open_cb);

        REQUIRE(sinit);

        auto client_endpoint = test_net.endpoint(client_local);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_stream_data_cb, client_stream_open_cb);

        std::thread client_native([&]() {
            auto client_stream = client_ci->get_new_stream();
            log::trace(log_cat, "Client sending stream message with native stream");
            client_stream->send(msg);
        });

        std::this_thread::sleep_for(100ms);

        std::thread server_thread([&]() {
            log::trace(log_cat, "Server sending stream message with extracted stream");
            server_extracted_stream->send(response);
            server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
            auto server_stream = server_ci->get_new_stream();
            log::trace(log_cat, "Server sending stream message with native stream");
            server_stream->send(msg);
        });

        std::this_thread::sleep_for(100ms);

        std::thread client_extracted([&]() {
            log::trace(log_cat, "Client sending stream message with extracted stream");
            client_extracted_stream->send(response);
        });

        std::this_thread::sleep_for(100ms);

        REQUIRE(stream_check.load() == 2);
        log::debug(log_cat, "Stream check count: {}", stream_check.load());
        REQUIRE(data_check.load() == 4);
        log::debug(log_cat, "Data check count: {}", data_check.load());

        client_native.join();
        server_thread.join();
        client_extracted.join();
        test_net.close();
    };
}  // namespace oxen::quic::test
