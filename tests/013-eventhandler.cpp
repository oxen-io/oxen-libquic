#include "unit_test.hpp"

namespace oxen::quic::test
{
    struct lifetime
    {};

    constexpr int NUM_ITERATIONS{4};
    constexpr auto INTERVAL{10ms};
    constexpr auto DELAY{2 * NUM_ITERATIONS * INTERVAL};

    TEST_CASE("013 - EventHandler event repeater: EventHandler managed lifetime", "[013][repeater][managed]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<void> prom_a, prom_b;
        std::future<void> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        std::shared_ptr<Ticker> handler;

        stream_data_callback server_data_cb = [&recv_counter](Stream&, std::span<const std::byte>) { recv_counter++; };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        handler = test_net.loop()->call_every(INTERVAL, [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                send_counter += 1;
                client_stream->send(msg, nullptr);
            }
        });

        handler->start();

        test_net.loop()->call_later(DELAY, [&prom_a] { prom_a.set_value(); });

        require_future(fut_a, 5s);
        REQUIRE(recv_counter == send_counter);

        recv_counter = 0;
        send_counter = 0;

        REQUIRE(handler->start());

        test_net.loop()->call_later(DELAY, [&prom_b] { prom_b.set_value(); });

        require_future(fut_b, 5s);
        REQUIRE(recv_counter == send_counter);
    }

    TEST_CASE("013 - Wakeable event handler", "[013][wakeable]")
    {
        Loop loop;

        std::promise<void> prom;
        std::atomic<int> i = 0;

        auto w = loop.make_wakeable([&i, &prom] {
            ++i;
            prom.set_value();
        });

        w->wake();
        auto fut = prom.get_future();

        require_future(fut, 1s);
        REQUIRE(i == 1);

        std::promise<void> prom2, prom5;
        w = loop.make_wakeable([&i, &prom2, &prom5] {
            auto v = ++i;
            if (v == 2)
                prom2.set_value();
            else if (v == 5)
                prom5.set_value();
        });

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });

        auto fut2 = prom2.get_future();
        require_future(fut2, 1s);
        REQUIRE(i == 2);

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });
        std::this_thread::sleep_for(25ms);
        w->wake();
        std::this_thread::sleep_for(25ms);
        w->wake();
        auto fut5 = prom5.get_future();
        require_future(fut5, 1s);
        REQUIRE(i == 5);
    }

}  //  namespace oxen::quic::test
