#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("003 - Multi-client to server transmission: Types", "[003][multi-client][types]")
    {
        SECTION("Multiple clients with the same address")
        {
            Network test_net{};

            opt::local_addr default_addr{};

            std::shared_ptr<Endpoint> client_b;

            auto client_a = test_net.endpoint(default_addr);

            REQUIRE_THROWS(client_b = test_net.endpoint(opt::remote_addr{"127.0.0.1"s, client_a->local().port()}));

            auto client_c = test_net.endpoint(default_addr);

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

        opt::local_addr server_local{};

        opt::local_addr client_a_local{};
        opt::local_addr client_b_local{};
        opt::local_addr client_c_local{};
        opt::local_addr client_d_local{};

        auto p_itr = stream_promises.begin();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            data_check += 1;
            p_itr->set_value(true);
            ++p_itr;
        };

        auto tls = defaults::tls_creds_from_ed_keys();
        const auto& client_tls = tls.first;
        const auto& server_tls = tls.second;

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

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
    };
}  // namespace oxen::quic::test
