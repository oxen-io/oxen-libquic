#include "unit_test.hpp"

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

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

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

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

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

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

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
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsp;

        std::promise<void> data_promise;
        std::future<void> data_future = data_promise.get_future();

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte>) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            data_promise.set_value();
        };
        std::atomic<bool> bad_call = false;
        dgram_data_callback overridden_dgram_cb = [&](dgram_interface&, std::vector<std::byte>) {
            log::critical(test_cat, "Wrong dgram callback invoked!");
            bad_call = true;
        };

        opt::enable_datagrams default_gram{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, default_gram, overridden_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, default_gram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

        conn_interface->send_datagram(msg, nullptr);

        require_future(data_future);
        CHECK_FALSE(bad_call);
    }

    TEST_CASE("007 - Datagram support: Execute, Packet Splitting Enabled", "[007][datagrams][execute][split][simple]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        std::atomic<int> data_counter{0};

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte> data) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");
            ++data_counter;
            if (data == "final"_bsp)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

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

        require_future(data_promise.get_future());
        CHECK(data_counter == 2);
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Clearing Buffer", "[007][datagrams][execute][split][rotating][clear]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        int data_counter = 0;
        int bufsize = 64, n = (bufsize / 2) + 1;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte>) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            if (++data_counter == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE, bufsize};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        auto max_size = conn_interface->get_max_datagram_size();

        std::vector<std::byte> good_msg{};
        unsigned char v{0};

        while (good_msg.size() < max_size)
            good_msg.push_back(static_cast<std::byte>(v++));

        for (int i = 0; i < n; ++i)
            conn_interface->send_datagram(good_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(data_counter == n);

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        REQUIRE(server_ci->last_cleared() == 0);
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Mixed Datagrams", "[007][datagrams][execute][split][rotating][mixed]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        int data_counter = 0;
        int n = 5;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte>) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            if (++data_counter == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        auto max_size = conn_interface->get_max_datagram_size();

        std::vector<std::byte> big_msg{}, small_msg{};
        unsigned char v{0};

        while (big_msg.size() < max_size)
            big_msg.push_back(std::byte{v++});

        while (small_msg.size() < 500)
            small_msg.push_back(std::byte{v++});

        conn_interface->send_datagram(big_msg, nullptr);
        conn_interface->send_datagram(big_msg, nullptr);
        conn_interface->send_datagram(small_msg, nullptr);
        conn_interface->send_datagram(big_msg, nullptr);
        conn_interface->send_datagram(small_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(data_counter == n);
    }

    TEST_CASE("007 - Datagram support: Rotating Buffer, Induced Loss", "[007][datagrams][execute][split][rotating][loss]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        int bufsize = 64, quarter = bufsize / 4;

        int counter = 0;

        std::promise<void> data_promise;

        std::vector<std::byte> received;

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte> data) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            received = std::move(data);

            if (++counter == bufsize)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE, (int)bufsize};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        std::vector<std::byte> dropped_msg(1500, std::byte{'-'});
        std::vector<std::byte> successful_msg(1500, std::byte{'+'});

        TestHelper::enable_dgram_drop(static_cast<Connection&>(*server_ci));

        for (int i = 0; i < quarter; ++i)
            conn_interface->send_datagram(dropped_msg, nullptr);

        while (TestHelper::get_dgram_debug_counter(*server_ci) < quarter)
            std::this_thread::sleep_for(10ms);

        TestHelper::disable_dgram_drop(*server_ci);

        for (int i = 0; i < bufsize; ++i)
            conn_interface->send_datagram(successful_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(counter == bufsize);
        REQUIRE(received == successful_msg);
    }

    /*
       Packet coalescing test.  When we send split packets, we have various levels of lookahead as
       to how much we will coalesce into a single packet.

       E.g. if we have packets [Aa] [Bb] [Cc] ... where the full packet is too big to fit in
       one quic datagram then a naive half split would result in sending [A] [a] [B] [b] [C] [c] ...
       in 2 quic packets per datagram.  However by alternating the order in which we send the two
       parts of the split we can coalesce the small parts together and send:
           [A] [ab] [B] [C] [cd] [D] ...
       using 3 quic packets for per 2 split datagrams, rather than 4 per 2 split datagrams.

       But we actually go further, and look ahead to see if there are other small pieces that we can
       include when trying to fill up an outgoing, partially filled packet, so that we could send:

           [A] [abcdefghij] [B] [C] [D] [E] [F] [G] [H] [I] [J]

       i.e. 10 datagrams in 11 packets.  (This depends, on course, on all the small a-j pieces
       fitting into one datagram, which will only be the case if the packets being sent are not too
       much over the splitting limit).
    */
    TEST_CASE("007 - Datagram support: Rotating Buffer, packet coalescing", "[007][datagrams][split][coalesce]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        std::atomic<int> data_counter{0};
        int n = 60;
        int target_dgrams;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte>) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            int count = ++data_counter;
            log::trace(test_cat, "Data counter: {}", count);
            if (count == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        // Give the connection time to figure out PMTU
        for (int i = 0; i < 10 && conn_interface->get_max_datagram_size() < 2796; i++)
            std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() == 2796);

        static constexpr size_t max_unsplit = 1398;
        // If we pack two small datagram pieces together then they get packed as:
        // QUIC OVERHEAD
        // DATAGRAM FRAME HEADER (3 bytes for datagrams >= 64B)
        // DGID (2 bytes)
        // DATA
        // DATAGRAM FRAME HEADER (3 bytes for datagrams >= 64B)
        // DGID (2 bytes)
        // DATA
        // and the 1398 is already accounting for the first three overhead lines.
        //
        // And so our maximum should be 696 because 1398 - 696 - 5 - 696 = 1 and so any big and we
        // should run over.  But that's not quite right, because that's a maximum while the actual
        // quic packet includes a 1-4 byte packet number.  Since this is a new connection, we can
        // assume the packets we test here will have 1-byte numbers, which gives us another 3 bytes
        // to work with, and that's where the `+3` comes from in this and later calculations.
        // (That's only for the first 256 quic packets, but that's enough for this test).
        static constexpr size_t max_two_packable = (max_unsplit + 3 - 5) / 2;
        size_t dgram_size = GENERATE(
                1,
                100,
                max_two_packable - 1,
                max_two_packable,
                max_two_packable + 1,
                1000,
                max_unsplit,
                max_unsplit + 1,
                max_unsplit + 50,
                max_unsplit + 100,
                max_unsplit + 500,
                max_unsplit + 1000,
                max_unsplit * 2);
        int lookahead = GENERATE(-1 /* should become the default, i.e. 8*/, 0, 1, 5, 10, 100);

        log::warning(log_cat, "DGRAM_SIZE: {}, LOOKAHEAD: {}", dgram_size, lookahead);
        conn_interface->set_split_datagram_lookahead(lookahead);

        if (dgram_size <= max_unsplit)
        {
            // max_unsplit already includes a deduction of 3 for the datagram frame and 2 for the
            // padding, so add those back in, then divide to see how many we can fit where each
            // include that 5 byte overhead:
            auto max_coalesced = (max_unsplit + 3 + 5) / (dgram_size + 5);
            log::warning(log_cat, "max coal: {}", max_coalesced);
            target_dgrams = n / max_coalesced;
        }
        else
        {
            // Packet splitting.  Every packet requires one full datagram for the big piece, but
            // then we also want to calculate how many small pieces we can coalesce together (with a
            // cap at lookahead + 2).
            auto packable = std::min<size_t>(
                    2 + (lookahead < 0 ? datagram_queue::DEFAULT_SPLIT_LOOKAHEAD : lookahead),
                    (max_unsplit + 3 + 5) / (dgram_size - max_unsplit + 5));
            log::warning(log_cat, "packable: {}", packable);
            target_dgrams = n + (n + packable - 1) / packable;
        }

        std::vector<std::byte> big;
        big.reserve(dgram_size);
        uint8_t v{0};

        while (big.size() < dgram_size)
            big.push_back(static_cast<std::byte>(v++));

        TestHelper::enable_dgram_counter(*conn_interface);

        std::promise<void> pr;

        client->call([&]() {
            for (int i = 0; i < n; i++)
                conn_interface->send_datagram(big, nullptr);

            pr.set_value();
        });

        require_future(pr.get_future());
        require_future(data_promise.get_future());

        REQUIRE(data_counter.load() == n);
        auto send_packet_count = TestHelper::disable_dgram_counter(*conn_interface);
        REQUIRE(send_packet_count >= target_dgrams);
        REQUIRE(send_packet_count <= target_dgrams + 5 /*fudge factor for other quic packet (ACKs, etc.)*/);
    }
}  // namespace oxen::quic::test
