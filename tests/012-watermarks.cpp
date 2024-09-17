#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    TEST_CASE("012 - Stream Buffer Watermarking", "[012][watermark][streams]")
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

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

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
                                log::debug(test_cat, "Executing low hook!");
                                low_count += 1;
                            },
                            true},
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(test_cat, "Executing high hook!");
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
                                log::debug(test_cat, "Executing low hook!");
                                low_count += 1;
                            },
                            true},
                    opt::watermark{
                            [&](const Stream&) {
                                log::debug(test_cat, "Executing high hook!");
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
}  //  namespace oxen::quic::test
