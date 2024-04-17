#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/datagram.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/opt.hpp>
#include <oxen/quic/types.hpp>
#include <oxen/quic/utils.hpp>
#include <stdexcept>
#include <thread>

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
        Address default_addr{};

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

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
    }

    TEST_CASE("007 - Datagram support: Query param info from datagram-disabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE_FALSE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE(conn_interface->get_max_datagram_size() == 0);
    }

    TEST_CASE("007 - Datagram support: Query param info from default datagram-enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::enable_datagrams default_gram{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, default_gram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, default_gram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_PMTUD_UDP_PAYLOAD);
    }

    TEST_CASE("007 - Datagram support: Query params from split-datagram enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);
    }

    TEST_CASE("007 - Datagram support: Execute, No Splitting Policy", "[007][datagrams][execute][nosplit]")
    {
        SECTION("Simple datagram transmission")
        {
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};
            auto msg = "hello from the other siiiii-iiiiide"_bsv;

            std::promise<void> data_promise;
            std::future<void> data_future = data_promise.get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                data_promise.set_value();
            };

            opt::enable_datagrams default_gram{};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, default_gram);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, default_gram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());
            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);
            REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

            conn_interface->send_datagram(msg);

            require_future(data_future);
        }
    }

    TEST_CASE("007 - Datagram support: Execute, Packet Splitting Enabled", "[007][datagrams][execute][split][simple]")
    {
        SECTION("Simple datagram transmission")
        {
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> data_counter{0};

            std::promise<void> data_promise;
            std::future<void> data_future = data_promise.get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring data) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");
                ++data_counter;
                if (data == "final"_bs)
                    data_promise.set_value();
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, split_dgram);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            auto init_max_size = conn_interface->max_datagram_size_changed();
            REQUIRE(init_max_size);
            CHECK(*init_max_size == 0);
            CHECK_FALSE(conn_interface->max_datagram_size_changed());

            REQUIRE(client_established.wait());
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

            auto max_size2 = conn_interface->max_datagram_size_changed();
            REQUIRE(max_size2);
            CHECK(*max_size2 == max_size);
            CHECK(*max_size2 > init_max_size);

            CHECK_FALSE(conn_interface->max_datagram_size_changed());

            CHECK(good_msg.size() <= max_size2);
            CHECK(oversize_msg.size() > max_size2);

            conn_interface->send_datagram(std::move(good_msg));
            conn_interface->send_datagram(std::move(oversize_msg));
            conn_interface->send_datagram("final"s);

            require_future(data_future);
            CHECK(data_counter == 2);
        }
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Clearing Buffer", "[007][datagrams][execute][split][rotating][clear]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        SECTION("Simple oversized datagram transmission - Clear first row")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            int bufsize = 16, n = (bufsize / 2) + 1;

            std::vector<std::promise<void>> data_promises{(size_t)n};
            std::vector<std::future<void>> data_futures{(size_t)n};

            for (int i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    data_promises.at(index).set_value();
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE, bufsize};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

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
                require_future(f);

            REQUIRE(data_counter == int(n));

            auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

            REQUIRE(server_ci->last_cleared() == 0);
        }
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Mixed Datagrams", "[007][datagrams][execute][split][rotating][mixed]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        SECTION("Simple datagram transmission - mixed sizes")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            size_t n = 5;

            std::vector<std::promise<void>> data_promises{n};
            std::vector<std::future<void>> data_futures{n};

            for (size_t i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    data_promises.at(index).set_value();
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

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
                require_future(f);

            REQUIRE(data_counter == int(n));
        }
    }

    TEST_CASE("007 - Datagram support: Rotating Buffer, Induced Loss", "[007][datagrams][execute][split][rotating][loss]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");
        SECTION("Simple datagram transmission - induced loss")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            int bufsize = 16, quarter = bufsize / 4;

            std::atomic<int> index{0}, counter{0};

            std::vector<std::promise<void>> data_promises{(size_t)bufsize};
            std::vector<std::future<void>> data_futures{(size_t)bufsize};

            for (int i = 0; i < bufsize; ++i)
                data_futures[i] = data_promises[i].get_future();

            bstring received{};

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring data) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                counter += 1;
                received.swap(data);

                try
                {
                    data_promises.at(index).set_value();
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE, (int)bufsize};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

            auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

            bstring dropped_msg(1500, std::byte{'-'});
            bstring successful_msg(1500, std::byte{'+'});

            TestHelper::enable_dgram_drop(static_cast<Connection&>(*server_ci));

            for (int i = 0; i < quarter; ++i)
                conn_interface->send_datagram(bstring_view{dropped_msg});

            while (TestHelper::get_dgram_debug_counter(*server_ci) < quarter)
                std::this_thread::sleep_for(10ms);

            TestHelper::disable_dgram_drop(*server_ci);

            for (int i = 0; i < bufsize; ++i)
                conn_interface->send_datagram(bstring_view{successful_msg});

            for (auto& f : data_futures)
                require_future(f);

            REQUIRE(counter == bufsize);
            REQUIRE(received == successful_msg);
        }
    }

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
        SECTION("Simple datagram transmission - flip flop ordering")
        {
            log::trace(log_cat, "Beginning the unit test from hell");
            auto client_established = callback_waiter{[](connection_interface&) {}};

            Network test_net{};

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            size_t n = 13;

            std::vector<std::promise<void>> data_promises{n};
            std::vector<std::future<void>> data_futures{n};

            for (size_t i = 0; i < n; ++i)
                data_futures[i] = data_promises[i].get_future();

            dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    log::trace(log_cat, "Data counter: {}", data_counter.load());
                    data_promises.at(index).set_value();
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            Address server_local{};
            Address client_local{};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram, client_established);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

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

            TestHelper::enable_dgram_flip_flop(*conn_interface);

            std::promise<void> pr;
            std::future<void> ftr = pr.get_future();

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

                pr.set_value();
            });

            require_future(ftr);

            for (auto& f : data_futures)
                require_future(f);

            REQUIRE(data_counter == (int)n);
            auto flip_flop_count = TestHelper::disable_dgram_flip_flop(*conn_interface);
            REQUIRE(flip_flop_count < (int)n);
        }
    }
}  // namespace oxen::quic::test
