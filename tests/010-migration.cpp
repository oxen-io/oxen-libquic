#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("010 - Migration", "[010][migration]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsp;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{}, client_secondary{}, client_local_b{};

        std::promise<void> d_promise;
        std::promise<void> conn_promise_a, conn_promise_b, conn_promise_c;

        auto d_future = d_promise.get_future();
        auto conn_future_a = conn_promise_a.get_future();
        auto conn_future_b = conn_promise_b.get_future();
        auto conn_future_c = conn_promise_c.get_future();

        std::atomic<bool> address_flipped = false, secondary_connected = false;

        std::shared_ptr<Endpoint> client_endpoint;
        std::shared_ptr<connection_interface> server_ci;

        stream_data_callback server_data_cb = [&](Stream&, bspan dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE_THAT(dat, EqualsSpan(good_msg));
            d_promise.set_value();
        };

        auto server_established = callback_waiter{[](connection_interface&) {}};
        auto client_established_b = callback_waiter{[](connection_interface&) { log::trace(test_cat, "LOOK ME UP BRO"); }};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        server_endpoint->listen(server_tls, server_data_cb);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = [&](connection_interface& ci) mutable {
            if (not address_flipped)
            {
                auto& conn = static_cast<Connection&>(ci);

                SECTION("NAT Rebinding")
                {
                    TestHelper::nat_rebinding(conn, client_secondary);
                }

                SECTION("Migration")
                {
                    TestHelper::migrate_connection(conn, client_secondary);
                }

                // Uncomment this when NGTCP2 releases v1.2.0
                SECTION("Immediate migration")
                {
                    TestHelper::migrate_connection_immediate(conn, client_secondary);
                }

                address_flipped = true;
                conn_promise_a.set_value();
            }
            else
            {
                if (not secondary_connected)
                {
                    log::trace(test_cat, "Skipping address flip!");
                    secondary_connected = true;
                    conn_promise_b.set_value();
                }
                else
                {
                    conn_promise_c.set_value();
                }
            }
        };

        client_endpoint = test_net.endpoint(client_local, client_established);
        auto original_addr = client_endpoint->local();
        client_endpoint->listen(client_tls);

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(server_established.wait());
        require_future(conn_future_a);

        auto client_stream = client_ci->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));
        require_future(d_future);

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        std::this_thread::sleep_for(5ms);
        RemoteAddress client_remote_b{defaults::CLIENT_PUBKEY, LOCALHOST, client_ci->local().port()};

        REQUIRE_FALSE(original_addr == client_ci->local());

        auto client_endpoint_b = test_net.endpoint(client_local_b, client_established_b);
        auto client_ci_b = client_endpoint_b->connect(client_remote_b, client_tls);

        require_future(conn_future_b);
        CHECK(client_established_b.wait());
    }
}  // namespace oxen::quic::test
