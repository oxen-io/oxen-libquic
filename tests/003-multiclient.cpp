#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("003 - Multi-client to server transmission: Types", "[003][multi-client][types]")
    {
        SECTION("Multiple clients with the same address")
        {
            Network test_net{};

            opt::local_addr default_addr{}, local_addr{"127.0.0.1"s, 4400};

            auto client_a = test_net.endpoint(local_addr);
            auto client_b = test_net.endpoint(local_addr);
            auto client_c = test_net.endpoint(default_addr);

            REQUIRE(client_a == client_b);
            REQUIRE_FALSE(client_a == client_c);
        };
    };

    TEST_CASE("003 - Multi-client to server transmission: Execution", "[003][multi-client][execute]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<int> data_check{0};
        std::vector<std::promise<bool>> stream_promises{4};
        std::vector<std::future<bool>> stream_futures{4};

        for (int i = 0; i < 4; ++i)
            stream_futures[i] = stream_promises[i].get_future();

        opt::local_addr server_local{"127.0.0.1"s, 5500};

        opt::local_addr client_a_local{"127.0.0.1"s, 4400};
        opt::local_addr client_b_local{"127.0.0.1"s, 4422};
        opt::local_addr client_c_local{"127.0.0.1"s, 4444};
        opt::local_addr client_d_local{"127.0.0.1"s, 4466};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto p_itr = stream_promises.begin();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            p_itr->set_value(true);
            ++p_itr;
            data_check += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_data_cb));

        std::thread async_thread_a{[&]() {
            log::debug(log_cat, "Async thread A called");

            // client A
            auto client_a = test_net.endpoint(client_a_local);
            auto c_interface_a = client_a->connect(client_remote, client_tls);

            // client B
            auto client_b = test_net.endpoint(client_b_local);
            auto c_interface_b = client_b->connect(client_remote, client_tls);

            // open streams
            auto stream_a = c_interface_a->get_new_stream();
            auto stream_b = c_interface_b->get_new_stream();

            // send
            stream_a->send(msg);
            stream_b->send(msg);
        }};

        std::thread async_thread_b{[&]() {
            log::debug(log_cat, "Async thread B called");

            // client C
            auto client_c = test_net.endpoint(client_c_local);
            auto c_interface_c = client_c->connect(client_remote, client_tls);

            // client D
            auto client_d = test_net.endpoint(client_d_local);
            auto c_interface_d = client_d->connect(client_remote, client_tls);

            // open streams
            auto stream_c = c_interface_c->get_new_stream();
            auto stream_d = c_interface_d->get_new_stream();

            // send
            stream_c->send(msg);
            stream_d->send(msg);
        }};

        for (auto& f : stream_futures)
            REQUIRE(f.get());

        async_thread_b.join();
        async_thread_a.join();
        REQUIRE(data_check == 4);
        test_net.close();
    };
}  // namespace oxen::quic::test
