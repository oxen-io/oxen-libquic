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

        std::atomic<int> index{0};
        std::atomic<int> data_check{0};
        opt::max_streams max_streams{8};
        std::vector<std::shared_ptr<Stream>> streams{12};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        std::vector<std::promise<bool>> send_promises{14}, receive_promises{13};
        std::vector<std::future<bool>> send_futures{14}, receive_futures{13};

        for (int i = 0; i < 13; ++i)
        {
            send_futures[i] = send_promises[i].get_future();
            receive_futures[i] = receive_promises[i].get_future();
        }
        send_futures[13] = send_promises[13].get_future();
        auto p_itr = receive_promises.begin();

        stream_data_callback_t server_stream_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");

            try {
                receive_promises.at(index).set_value(true);
                ++index;
                data_check += 1;
            } catch (std::exception& e) {
                throw std::runtime_error(e.what());
            }
        };

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, max_streams, server_stream_data_cb));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        // 1) open 12 streams and send
        for (int i = 0; i < 12; ++i)
        {
            std::thread stream_thread([&](){
                streams[i] = conn_interface->get_new_stream();
                streams[i]->send(msg);
                // set send promises
                send_promises[i].set_value(true);
            });
            stream_thread.join();
        }

        // 2) check the first 8
        for (int i = 0; i < 8; ++i)
            REQUIRE(receive_futures[i].get());

        // 3) close 4 streams
        for (int i = 0; i < 5; ++i)
        {
            std::thread close_thread([&](){
                streams[i]->close();
            });
            close_thread.join();
        }

        // 4) check the last 4
        for (int i = 8; i < 12; ++i)
            REQUIRE(receive_futures[i].get());

        // 5) open 2 more streams and send
        for (int i = 0; i < 2; ++i)
        {
            std::thread open_thread([&](){
                streams[i] = conn_interface->get_new_stream();
                streams[i]->send(msg);
                // set send promise
                send_promises[i+12].set_value(true);
            });
            open_thread.join();
        }

        // 6) check final stream received data
        REQUIRE(receive_futures[12].get());

        // 7) verify
        for (auto& f : send_futures)
            REQUIRE(f.get());

        auto* conn = client_endpoint->get_conn(conn_interface->scid());

        REQUIRE(conn);
        REQUIRE(conn->num_pending() == 1);
        REQUIRE(data_check == 13);

        test_net.close();
    };
}  // namespace oxen::quic::test
