#include "quic.hpp"

#include <catch2/catch_test_macros.hpp>
#include <thread>


namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("Simple client to server transmission")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of DTLS handshake...");

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;
        bool run{true};

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
            ""s};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        std::thread ev_thread{[&](){
            test_net.run();

            size_t counter = 0;
            do
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
                if (++counter % 30 == 0)
                    std::cout << "waiting..." << "\n";
            } while (run);
        }};

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        std::thread async_thread([&](){
            auto stream = client->open_stream();
            stream->send(msg);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            REQUIRE(run);
        });

        test_net.ev_loop->close();
        async_thread.join();
        ev_thread.detach();
    };
}
