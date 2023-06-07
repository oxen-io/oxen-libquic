#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("003: Multi-client to server transmission", "[003][multi-client]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of multi-client connection...");

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<bool> good{false};

        server_data_callback_t server_data_cb = [&](const uvw::udp_data_event& event, uvw::udp_handle& udp) {
            log::debug(log_cat, "Calling server data callback... data received...");
            good = true;
        };

        opt::server_tls server_tls{"./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        opt::client_tls client_tls{"./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s};

        opt::local_addr client_a_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::local_addr client_b_local{"127.0.0.1"s, static_cast<uint16_t>(4422)};
        opt::local_addr client_c_local{"127.0.0.1"s, static_cast<uint16_t>(4444)};
        opt::local_addr client_d_local{"127.0.0.1"s, static_cast<uint16_t>(4466)};
        opt::remote_addr client_a_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::remote_addr client_b_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::remote_addr client_c_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::remote_addr client_d_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls, server_data_cb);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client_a = test_net.client_connect(client_a_local, client_a_remote, client_tls);
        auto client_b = test_net.client_connect(client_b_local, client_b_remote, client_tls);

        std::thread ev_thread{[&]() { test_net.run(); }};

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        std::thread async_thread_a{[&]() {
            log::debug(log_cat, "Async thread 1 called");

            auto client_c = test_net.client_connect(client_c_local, client_c_remote, client_tls);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            auto stream_a = client_a->open_stream();
            stream_a->send(msg);

            auto stream_b = client_b->open_stream();
            stream_b->send(msg);

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            auto stream_c = client_c->open_stream();
            stream_c->send(msg);
        }};

        std::thread async_thread_b{[&]() {
            log::debug(log_cat, "Async thread 2 called");

            auto client_d = test_net.client_connect(client_d_local, client_d_remote, client_tls);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            auto stream_d = client_d->open_stream();
            stream_d->send(msg);
        }};

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        REQUIRE(good);
        test_net.close();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        test_net.ev_loop->close();
        async_thread_a.join();
        async_thread_b.join();
        ev_thread.detach();
    };
}  // namespace oxen::quic::test
