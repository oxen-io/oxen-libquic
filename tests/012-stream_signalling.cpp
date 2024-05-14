#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    TEST_CASE("012 - Stream Signalling: Buffer Watermarking", "[012][signalling][watermark][streams]")
    {
        Network test_net{};
        bstring req_msg(100'000, std::byte{'a'});

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto client_stream = conn_interface->open_stream();

        CHECK_FALSE(client_stream->has_watermarks());

        SECTION("Watermarks self-clear")
        {
            auto low_water = callback_waiter{[](Stream&) {}};
            auto high_water = callback_waiter{[](Stream&) {}};
            client_stream->set_watermark(500, 1000, opt::watermark{low_water, false}, opt::watermark{high_water, false});

            CHECK(client_stream->has_watermarks());

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            CHECK(low_water.wait());

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            CHECK(high_water.wait());

            REQUIRE_FALSE(client_stream->has_watermarks());
        }

        SECTION("Watermarks persist")
        {
            std::atomic<int> low_count{0}, high_count{0};

            client_stream->set_watermark(
                    500,
                    2000,
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(log_cat, "Executing low hook!");
                                low_count += 1;
                            },
                            true},
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(log_cat, "Executing high hook!");
                                high_count += 1;
                            },
                            true});

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            std::this_thread::sleep_for(100ms);

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            std::this_thread::sleep_for(250ms);

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            std::this_thread::sleep_for(250ms);

            REQUIRE(low_count >= 2);
            REQUIRE(high_count >= 1);
            REQUIRE(low_count >= high_count);

            client_stream->clear_watermarks();

            REQUIRE_FALSE(client_stream->has_watermarks());
        }

        SECTION("Watermarks persist; server stream pausing")
        {
            std::atomic<int> low_count{0}, high_count{0};

            client_stream->set_watermark(
                    500,
                    2000,
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(log_cat, "Executing low hook!");
                                low_count += 1;
                            },
                            true},
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(log_cat, "Executing high hook!");
                                high_count += 1;
                            },
                            true});

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            std::this_thread::sleep_for(100ms);

            auto server_stream = server_endpoint->get_all_conns().front()->get_stream(client_stream->stream_id());
            REQUIRE(server_stream != nullptr);

            server_stream->pause();
            REQUIRE(server_stream->is_paused());

            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));
            REQUIRE_NOTHROW(client_stream->send(bstring_view{req_msg}));

            server_stream->resume();
            REQUIRE_FALSE(server_stream->is_paused());
            std::this_thread::sleep_for(500ms);  // stupid debian sid ARM64 CI

            REQUIRE(low_count >= 2);
            REQUIRE(high_count >= 1);

            client_stream->clear_watermarks();

            REQUIRE_FALSE(client_stream->has_watermarks());
        }
    }

    TEST_CASE("012 - Stream Signalling: Stop Read/Write", "[012][signalling][readwrite][streams]")
    {
        Network test_net{};
        bstring req_msg(1'000, std::byte{'a'});

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::shared_ptr<Stream> server_stream;

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[&](connection_interface& ci) {
            server_stream = ci.queue_incoming_stream();
            server_stream->send(bstring_view{req_msg});
        }};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto p = std::promise<bool>();
        auto f = p.get_future();

        auto client_stream = conn_interface->open_stream<Stream>([&](Stream&, bstring_view) { p.set_value(true); });

        SECTION("Stop Writing")
        {
            client_stream->set_remote_reset_hooks(opt::remote_stream_reset{
                    [](Stream& s, uint64_t ec) {
                        REQUIRE(ec == STREAM_REMOTE_READ_SHUTDOWN);

                        // Cannot set or clear callbacks while executing the callbacks!
                        REQUIRE_THROWS(s.set_remote_reset_hooks(opt::remote_stream_reset{}));
                        REQUIRE_THROWS(s.clear_remote_reset_hooks());
                        s.stop_reading();
                    },
                    [](Stream& s, uint64_t ec) {
                        REQUIRE(ec == STREAM_REMOTE_WRITE_SHUTDOWN);
                        s.stop_writing();
                    }});

            REQUIRE(client_stream->is_reading());
            REQUIRE(client_stream->is_writing());

            server_stream->stop_writing();
            REQUIRE_FALSE(server_stream->is_writing());

            client_stream->send(bstring_view{req_msg});
            require_future(f);

            // allow the acks to get back to the client; extra time for slow CI archs
            std::this_thread::sleep_for(250ms);

            REQUIRE_FALSE(client_stream->is_reading());

            REQUIRE(TestHelper::stream_unacked(*server_stream.get()) == 0);
        }

        SECTION("Stop Reading")
        {
            server_stream->set_remote_reset_hooks(opt::remote_stream_reset{
                    [](Stream& s, uint64_t ec) {
                        REQUIRE(ec == STREAM_REMOTE_READ_SHUTDOWN);

                        // Cannot set or clear callbacks while executing the callbacks!
                        REQUIRE_THROWS(s.set_remote_reset_hooks(opt::remote_stream_reset{}));
                        REQUIRE_THROWS(s.clear_remote_reset_hooks());
                        s.stop_reading();
                    },
                    [](Stream& s, uint64_t ec) {
                        REQUIRE(ec == STREAM_REMOTE_WRITE_SHUTDOWN);
                        s.stop_writing();
                    }});

            REQUIRE(server_stream->is_reading());
            REQUIRE(server_stream->is_writing());

            client_stream->stop_reading();
            REQUIRE_FALSE(client_stream->is_reading());

            client_stream->send(bstring_view{req_msg});

            REQUIRE(f.wait_for(1s) == std::future_status::timeout);
        }
    }
}  //  namespace oxen::quic::test
