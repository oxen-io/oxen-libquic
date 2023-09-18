#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <stdexcept>
#include <thread>

#include "quic/connection.hpp"
#include "quic/datagram.hpp"
#include "quic/opt.hpp"
#include "quic/types.hpp"
#include "quic/utils.hpp"
#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("007 - Datagram support: Default type construction", "[007][datagrams][types]")
    {
        Network test_net{};

        const int bsize = 256;

        opt::enable_datagrams default_dgram{},          // packet_splitting = false
                split_dgram{Splitting::ACTIVE},         // packet_splitting = true, policy = ::ACTIVE
                bsize_dgram{Splitting::ACTIVE, bsize};  // bufsize = 256
        opt::local_addr default_addr{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

        // datagrams = false, packet_splitting = false, splitting_policy = ::NONE
        auto vanilla_ep = test_net.endpoint(default_addr);
        REQUIRE_NOTHROW(vanilla_ep->listen(server_tls));

        REQUIRE_FALSE(vanilla_ep->datagrams_enabled());
        REQUIRE_FALSE(vanilla_ep->packet_splitting_enabled());
        REQUIRE(vanilla_ep->splitting_policy() == Splitting::NONE);

        // datagrams = true, packet_splitting = false, splitting_policy = ::NONE
        auto default_ep = test_net.endpoint(default_addr, default_dgram);
        REQUIRE_NOTHROW(default_ep->listen(server_tls));

        REQUIRE(default_ep->datagrams_enabled());
        REQUIRE_FALSE(default_ep->packet_splitting_enabled());
        REQUIRE(default_ep->splitting_policy() == Splitting::NONE);

        // datagrams = true, packet_splitting = true
        auto splitting_ep = test_net.endpoint(default_addr, split_dgram);
        REQUIRE_NOTHROW(splitting_ep->listen(server_tls));

        REQUIRE(splitting_ep->datagrams_enabled());
        REQUIRE(splitting_ep->packet_splitting_enabled());
        REQUIRE(splitting_ep->splitting_policy() == Splitting::ACTIVE);

        // datagrams = true, packet_splitting = true
        auto bufsize_ep = test_net.endpoint(default_addr, bsize_dgram);
        REQUIRE_NOTHROW(bufsize_ep->listen(server_tls));

        REQUIRE(bufsize_ep->datagrams_enabled());
        REQUIRE(bufsize_ep->packet_splitting_enabled());
        REQUIRE(bufsize_ep->splitting_policy() == Splitting::ACTIVE);
        REQUIRE(bufsize_ep->datagram_bufsize() == bsize);
    };

    TEST_CASE("007 - Datagram support: Query param info from datagram-disabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = bool_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait_ready());
        REQUIRE_FALSE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE(conn_interface->get_max_datagram_size() == 0);
    };

    TEST_CASE("007 - Datagram support: Query param info from default datagram-enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = bool_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::enable_datagrams default_gram{};

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local, default_gram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, default_gram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait_ready());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_PMTUD_UDP_PAYLOAD);
    };

    TEST_CASE("007 - Datagram support: Query params from split-datagram enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = bool_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};
        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local, split_dgram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.get());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);
    };

    TEST_CASE("007 - Datagram support: Execute, No Splitting Policy", "[007][datagrams][execute][nosplit]")
    {
        SECTION("Simple datagram transmission")
        {
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};
            auto msg = "hello from the other siiiii-iiiiide"_bsv;

            std::promise<bool> data_promise;
            std::future<bool> data_future = data_promise.get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                data_promise.set_value(true);
            };

            opt::enable_datagrams default_gram{};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, default_gram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, default_gram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());
            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);
            REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

            conn_interface->send_datagram(msg);

            REQUIRE(data_future.get());
        };
    };

    TEST_CASE("007 - Datagram support: Execute, Packet Splitting Enabled", "[007][datagrams][execute][split][simple]")
    {
        SECTION("Simple datagram transmission")
        {
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> data_counter{0};

            std::promise<bool> data_promise;
            std::future<bool> data_future = data_promise.get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");
                data_counter += 1;
                data_promise.set_value(true);
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());
            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);
            auto max_size = conn_interface->get_max_datagram_size();

            std::string good_msg{}, oversize_msg{};
            char v = 0;

            while (good_msg.size() < max_size)
                good_msg += v++;
            v = 0;
            while (oversize_msg.size() < max_size * 2)
                oversize_msg += v++;

            REQUIRE_NOTHROW(conn_interface->send_datagram(std::move(good_msg)));
            REQUIRE_THROWS(conn_interface->send_datagram(std::move(oversize_msg)));

            REQUIRE(data_future.get());
            REQUIRE(data_counter == 1);
        };
    };

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Clearing Buffer", "[007][datagrams][execute][split][rotating][clear]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        SECTION("Simple oversized datagram transmission - Clear first row")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            int bufsize = 16, n = (bufsize / 2) + 1;

            std::vector<std::promise<bool>> data_promises{(size_t)n};
            std::vector<std::future<bool>> data_futures{(size_t)n};

            for (int i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    data_promises.at(index).set_value(true);
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE, bufsize};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());

            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);
            auto max_size = conn_interface->get_max_datagram_size();

            std::basic_string<uint8_t> good_msg{};
            uint8_t v{0};

            while (good_msg.size() < max_size)
                good_msg += v++;

            for (int i = 0; i < n; ++i)
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{good_msg});

            for (auto& f : data_futures)
                REQUIRE(f.get());

            REQUIRE(data_counter == int(n));

            auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

            REQUIRE(server_ci->last_cleared() == 0);
        };
    };

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Mixed Datagrams", "[007][datagrams][execute][split][rotating][mixed]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        SECTION("Simple datagram transmission - mixed sizes")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            size_t n = 5;

            std::vector<std::promise<bool>> data_promises{n};
            std::vector<std::future<bool>> data_futures{n};

            for (size_t i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    data_promises.at(index).set_value(true);
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());

            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);
            auto max_size = conn_interface->get_max_datagram_size();

            std::basic_string<uint8_t> big_msg{}, small_msg{};
            uint8_t v{0};

            while (big_msg.size() < max_size)
                big_msg += v++;

            while (small_msg.size() < 500)
                small_msg += v++;

            conn_interface->send_datagram(std::basic_string_view<uint8_t>{big_msg});
            conn_interface->send_datagram(std::basic_string_view<uint8_t>{big_msg});
            conn_interface->send_datagram(std::basic_string_view<uint8_t>{small_msg});
            conn_interface->send_datagram(std::basic_string_view<uint8_t>{big_msg});
            conn_interface->send_datagram(std::basic_string_view<uint8_t>{small_msg});

            for (auto& f : data_futures)
                REQUIRE(f.get());

            REQUIRE(data_counter == int(n));
        };
    };

    TEST_CASE("007 - Datagram support: Rotating Buffer, Induced Loss", "[007][datagrams][execute][split][rotating][loss]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");
#ifdef NDEBUG
        SKIP("Induced test loss requires a debug build");
#else
        SECTION("Simple datagram transmission - induced loss")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};

            int bufsize = 16, quarter = bufsize / 4;

            std::atomic<int> index{0}, counter{0};

            std::vector<std::promise<bool>> data_promises{(size_t)bufsize};
            std::vector<std::future<bool>> data_futures{(size_t)bufsize};

            for (int i = 0; i < bufsize; ++i)
                data_futures[i] = data_promises[i].get_future();

            bstring received{};

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring data) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                counter += 1;
                received.swap(data);

                try
                {
                    data_promises.at(index).set_value(true);
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE, (int)bufsize};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());

            auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

            bstring dropped_msg(1500, std::byte{'-'});
            bstring successful_msg(1500, std::byte{'+'});

            server_ci->test_suite.datagram_drop_counter = 0;
            server_ci->test_suite.datagram_drop_enabled = true;

            for (int i = 0; i < quarter; ++i)
                conn_interface->send_datagram(bstring_view{dropped_msg});

            while (server_ci->test_suite.datagram_drop_counter < quarter)
                std::this_thread::sleep_for(10ms);

            server_ci->test_suite.datagram_drop_enabled = false;

            for (int i = 0; i < bufsize; ++i)
                conn_interface->send_datagram(bstring_view{successful_msg});

            for (auto& f : data_futures)
                REQUIRE(f.get());

            REQUIRE(counter == bufsize);
            REQUIRE(received == successful_msg);
        };
#endif
    };

    /*
        Test Note:
            Flip flop packet ordering is hard to exactly quantify the magnitude of its optimization. On premise, it takes
            big split datagrams queued next and sends their small portion first.

            For example, with 13 calls to send_datagram, we caan accurately predict that the number of packets sent is
            less than 13. The extent to which this is optimized depends on the datagram sizes being sent, whether ngtcp2
            sends acks or other frames, and other protocol level things.
    */
    TEST_CASE("007 - Datagram support: Rotating Buffer, Flip-Flop Ordering", "[007][datagrams][execute][split][flipflop]")
    {
#ifdef NDEBUG
        SKIP("Induced test loss requires a debug build");
#else
        SECTION("Simple datagram transmission - flip flop ordering")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = bool_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            size_t n = 13;

            std::vector<std::promise<bool>> data_promises{n};
            std::vector<std::future<bool>> data_futures{n};

            for (size_t i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    log::trace(log_cat, "Data counter: {}", data_counter.load());
                    data_promises.at(index).set_value(true);
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait_ready());

            std::this_thread::sleep_for(5ms);
            auto max_size = conn_interface->get_max_datagram_size();

            std::basic_string<uint8_t> big{}, medium{}, small{};
            uint8_t v{0};

            while (big.size() < max_size * 2 / 3)
                big += v++;

            while (medium.size() < max_size / 2 - 100)
                medium += v++;

            while (small.size() < 50)
                small += v++;

            conn_interface->test_suite.datagram_flip_flip_counter = 0;
            conn_interface->test_suite.datagram_flip_flop_enabled = true;

            std::promise<bool> pr;
            std::future<bool> ftr = pr.get_future();

            client->call([&]() {
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{big});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{big});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{big});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{medium});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{big});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});
                conn_interface->send_datagram(std::basic_string_view<uint8_t>{small});

                pr.set_value(true);
            });

            REQUIRE(ftr.get());

            for (auto& f : data_futures)
                REQUIRE(f.get());

            REQUIRE(data_counter == int(n));
            REQUIRE(conn_interface->test_suite.datagram_flip_flip_counter < (int)n);

            conn_interface->test_suite.datagram_flip_flop_enabled = false;
        };
#endif
    };
}  // namespace oxen::quic::test
