#include "unit_test.hpp"

#include <catch2/matchers/catch_matchers_predicate.hpp>
#include <catch2/matchers/catch_matchers_quantifiers.hpp>

namespace oxen::quic::test
{
    TEST_CASE("012 - Stream Buffer Watermarking", "[012][watermark][streams]")
    {
        Loop loop;
        std::vector<std::byte> huge_msg(100'000, std::byte{'a'});
        auto trigger_msg = std::span{huge_msg}.first(2000);

        auto client_established = callback_waiter{[](Connection&) {}};
        auto server_established = callback_waiter{[](Connection&) {}};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::atomic<size_t> server_received = 0;
        auto server_endpoint = Endpoint::endpoint(loop, server_local, server_established);
        server_endpoint->listen(server_tls, [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            server_received += dat.size();
        });

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = Endpoint::endpoint(loop, client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto client_stream = conn_interface->open_stream();

        auto stat = client_stream->watermark_status();
        CHECK_FALSE(stat);

        std::atomic<int> clear_count{0}, alarm_count{0};

        SECTION("basic functionality")
        {
            client_stream->enable_watermarks(
                    2000,
                    [&](Stream&) {
                        log::debug(test_cat, "Alarm hook called!");
                        alarm_count++;
                    },
                    0,
                    [&](Stream&) {
                        log::debug(test_cat, "All-clear hook called");
                        clear_count++;
                    });

            client_stream->send(trigger_msg.first(1999), nullptr);
            bool s_recvd = wait_for([&] { return server_received.load() >= 1999; }, 100ms);
            REQUIRE(s_recvd);
            CHECK(server_received == 1999);
            CHECK(clear_count == 0);
            CHECK(alarm_count == 0);
            stat = client_stream->watermark_status();
            CHECK(stat);
            CHECK_FALSE(*stat);

            server_received = 0;
            loop.call_get([&] {
                client_stream->send(trigger_msg, nullptr);
                stat = client_stream->watermark_status();
                // The above should have triggered the watermark alarm (we need to check it in this
                // same call_get() so that there isn't a race with actually sending the data out.)
                CHECK(stat);
                CHECK(*stat);
                CHECK(clear_count == 0);
                CHECK(alarm_count == 1);
            });
            s_recvd = wait_for([&] { return server_received.load() >= trigger_msg.size(); }, 100ms);
            CHECK(s_recvd);
            CHECK(server_received == trigger_msg.size());
            CHECK(clear_count == 1);
            CHECK(alarm_count == 1);

            // Try the same, but with many tiny buffers:
            server_received = 0;
            loop.call_get([&] {
                auto one = trigger_msg.first(1);
                for (size_t i = 1; i < trigger_msg.size(); i++)
                    client_stream->send(one, nullptr);
                stat = client_stream->watermark_status();
                CHECK(stat);
                CHECK_FALSE(*stat);
                CHECK(clear_count == 1);
                CHECK(alarm_count == 1);
                client_stream->send(one, nullptr);
                stat = client_stream->watermark_status();
                CHECK(stat);
                CHECK(*stat);
                CHECK(clear_count == 1);
                CHECK(alarm_count == 2);
            });
            s_recvd = wait_for([&] { return server_received.load() >= trigger_msg.size(); }, 100ms);
            CHECK(s_recvd);
            CHECK(server_received == trigger_msg.size());
            stat = client_stream->watermark_status();
            CHECK(stat);
            CHECK_FALSE(*stat);
            CHECK(clear_count == 2);
            CHECK(alarm_count == 2);
        }

        SECTION("watermark reset triggers immediately")
        {
            client_stream->enable_watermarks(2000, nullptr, 0, nullptr);

            loop.call_get([&] {
                client_stream->send(trigger_msg.first(1500), nullptr);
                stat = client_stream->watermark_status();
                CHECK(stat);
                CHECK_FALSE(*stat);

                bool alarm_triggered = false, alarm_cleared = false;
                auto alarm = [&](auto&&) { alarm_triggered = true; };
                auto clear = [&](auto&&) { alarm_cleared = true; };
                // Should not retrigger when buffer is < the new limit
                client_stream->enable_watermarks(1501, alarm, 0, clear);
                CHECK_FALSE(alarm_triggered);
                CHECK_FALSE(alarm_cleared);
                CHECK_FALSE(*client_stream->watermark_status());

                // Should retrigger when current buffer is >= the new limit
                alarm_triggered = alarm_cleared = false;
                client_stream->enable_watermarks(1100, alarm, 0, clear);
                CHECK(alarm_triggered);
                CHECK_FALSE(alarm_cleared);
                CHECK(*client_stream->watermark_status());

                // Should not *retrigger* when already in the alarm state
                alarm_triggered = alarm_cleared = false;
                client_stream->enable_watermarks(1200, alarm, 0, clear);
                CHECK_FALSE(alarm_triggered);
                CHECK_FALSE(alarm_cleared);
                CHECK(*client_stream->watermark_status());

                // Should not clear because new clear value is < current buffer:
                alarm_triggered = alarm_cleared = false;
                client_stream->enable_watermarks(2000, alarm, 1499, clear);
                CHECK_FALSE(alarm_triggered);
                CHECK_FALSE(alarm_cleared);
                CHECK(*client_stream->watermark_status());

                // Should clear because new clear value is >= current buffer:
                alarm_triggered = alarm_cleared = false;
                client_stream->enable_watermarks(2000, alarm, 1500, clear);
                CHECK_FALSE(alarm_triggered);
                CHECK(alarm_cleared);
                CHECK_FALSE(*client_stream->watermark_status());
            });
        }

        SECTION("large buffer with positive clear watermark")
        {
            // Now we set the watermarks to use much larger thresholds, and then we send enough at
            // once that it can't possible all be sent in one pass of the connection packet
            // flushing, which means we should see a clear call with some unsent data still in the
            // stream buffers.
            std::atomic<size_t> clear_hook_unsent = 0, alarm_hook_unsent = 0;
            client_stream->enable_watermarks(
                    80'000,
                    [&](Stream& s) {
                        log::debug(test_cat, "Alarm hook!");
                        alarm_count++;
                        alarm_hook_unsent = s.unsent();
                    },
                    50'000,
                    [&](Stream& s) {
                        log::debug(test_cat, "All-clear hook");
                        clear_count++;
                        clear_hook_unsent = s.unsent();
                    });
            stat = client_stream->watermark_status();
            CHECK(stat);
            CHECK_FALSE(*stat);

            server_received = 0;
            loop.call_get([&] {
                client_stream->send(huge_msg, nullptr);
                stat = client_stream->watermark_status();
                CHECK(stat);
                CHECK(*stat);
                CHECK(clear_count == 0);
                CHECK(alarm_count == 1);
            });
            bool s_recvd = wait_for([&] { return server_received.load() >= huge_msg.size(); }, 1s);
            CHECK(s_recvd);
            stat = client_stream->watermark_status();
            CHECK(stat);
            CHECK_FALSE(*stat);
            CHECK(clear_count == 1);
            CHECK(alarm_count == 1);
            CHECK(clear_hook_unsent > 0);
            CHECK(clear_hook_unsent <= 50'000);
            CHECK(alarm_hook_unsent == 100'000);
        }

        SECTION("large buffer with more data fed during clear hooks")
        {
            std::vector<size_t> clear_hook_unsent, alarm_hook_unsent;

            client_stream->enable_watermarks(
                    80'000,
                    [&](Stream& s) {
                        log::debug(test_cat, "Alarm!");
                        ++alarm_count;
                        CHECK(alarm_count == clear_count + 1);
                        alarm_hook_unsent.push_back(s.unsent());
                    },
                    40'000,
                    [&](Stream& s) {
                        log::debug(test_cat, "All clear");
                        clear_hook_unsent.push_back(s.unsent());
                        auto c = ++clear_count;
                        CHECK(alarm_count == c);
                        if (c <= 3)
                            s.send(huge_msg, nullptr);
                    });

            client_stream->send(huge_msg, nullptr);
            bool s_recvd = wait_for([&] { return server_received.load() >= 4 * huge_msg.size(); }, 2s);
            CHECK(s_recvd);
            stat = client_stream->watermark_status();
            CHECK(stat);
            CHECK_FALSE(*stat);
            CHECK(clear_count == 4);
            CHECK(alarm_count == 4);
            CHECK(clear_hook_unsent.size() == 4);
            CHECK(alarm_hook_unsent.size() == 4);
            using namespace Catch::Matchers;
            CHECK_THAT(
                    clear_hook_unsent,
                    AllMatch(Predicate<size_t>([](size_t x) { return x <= 40'000; }, "unsent data when clear hook called")));
            CHECK_THAT(
                    alarm_hook_unsent,
                    AllMatch(Predicate<size_t>([](size_t x) { return x >= 80'000; }, "unsent data when alarm hook called")));
        }
    }
}  //  namespace oxen::quic::test
