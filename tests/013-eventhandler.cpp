#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    struct lifetime
    {};

    constexpr int NUM_ITERATIONS{10};
    constexpr auto INTERVAL{10ms};
    constexpr auto DELAY{2 * NUM_ITERATIONS * INTERVAL};

    TEST_CASE("013 - EventHandler event repeater: EventHandler managed lifetime", "[013][repeater][managed]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<void> prom_a, prom_b;
        std::future<void> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        std::shared_ptr<Ticker> handler;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            recv_counter += 1;
            if (recv_counter == NUM_ITERATIONS)
            {
                handler->stop();
            }
        };

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

        handler = test_net.call_every(INTERVAL, [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                send_counter += 1;
                client_stream->send(msg);
            }
        });

        handler->start();

        REQUIRE(handler->is_running());
        test_net.call_later(DELAY, [&]() { prom_a.set_value(); });

        require_future(fut_a, 5s);
        REQUIRE(recv_counter == send_counter);
        REQUIRE_FALSE(handler->is_running());

        recv_counter = 0;
        send_counter = 0;

        REQUIRE(handler->start());

        test_net.call_later(DELAY, [&]() { prom_b.set_value(); });

        require_future(fut_b, 5s);
        REQUIRE(recv_counter == send_counter);
        REQUIRE_FALSE(handler->is_running());
    }
}  //  namespace oxen::quic::test
