#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("014 - 0-RTT", "[014][0rtt]")
    {
        if (disable_0rtt)
            SKIP("0-RTT tests not enabled for this test iteration!");

        // This case checks that, even if we enable 0-RTT, without having the needed ticket on hand
        // we fall back to the expected 1-RTT.

        std::promise<void> server_established_prom;
        auto server_established = [&server_established_prom](connection_interface&) { server_established_prom.set_value(); };
        std::promise<void> client_established_prom;
        auto client_established = [&client_established_prom](connection_interface&) { client_established_prom.set_value(); };

        Network net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();
        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        Address server_local{LOCALHOST, 0};
        Address client_local{LOCALHOST, 0};

        auto delayer = packet_delayer::make(0ms);  // no delay initially, but we'll ramp it up later
        auto client_endpoint = net.endpoint(client_local, opt::enable_datagrams{}, *delayer);
        delayer->init(std::make_shared<Loop>(), client_endpoint);

        std::vector<unsigned char> server_secret;
        server_secret.resize(32);
        gnutls_rnd(GNUTLS_RND_RANDOM, server_secret.data(), server_secret.size());

        auto server_endpoint =
                net.endpoint(server_local, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});

        auto server_stream_cb = [](Stream& s, std::span<const std::byte> data) {
            log::debug(log_cat, "server stream got {} stream bytes", data.size());
            s.send("OK"s);
        };
        auto server_dgram_cb = [](dgram_interface& d, std::span<const std::byte> data) {
            log::debug(log_cat, "server received {}B datagram", data.size());
            d.reply("OK"s);
        };
        server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);

        auto server_addr = server_endpoint->local();

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, server_addr};

        // How many latency we expect until we get a response to our stream/datagram.  1 for 0-RTT
        // (i.e. 0-RTT means no additional establishing latency), 2 for 1-RTT (i.e. 1-RTT to
        // establish and then one to send and receive).
        int expected_rtt = 1;

        SECTION("0-RTT not available")
        {
            // Without a prior connection there will be no 0-RTT data for us to try with, so we
            // should just do a plain 1-RTT without even trying early data.
            expected_rtt = 2;
        }
        SECTION("0-RTT attempted")
        {
            // We have to connect successfully first to collect the session tickets and transport
            // params in the client_tls creds, then disconnect, and reconnect again to actually make
            // 0-RTT happen.
            auto first_ci = client_endpoint->connect(client_remote, client_tls, client_established);

            require_future(client_established_prom.get_future());
            require_future(server_established_prom.get_future());

            server_established_prom = std::promise<void>{};
            client_established_prom = std::promise<void>{};

            // TLS tickets can arrive just after the handshake confirmed packet, so add a tiny
            // extra wait to allow for them to arrive.
            std::this_thread::sleep_for(5ms);

            first_ci->close_connection();
            first_ci.reset();

            std::this_thread::sleep_for(5ms);

            SECTION("0-RTT successful")
            {
                expected_rtt = 1;
            }

            SECTION("0-RTT successful - new server listening with same TLS creds")
            {
                // Restart the server listener with the same tls creds, which should be fine.
                expected_rtt = 1;

                net.close(std::move(server_endpoint));
                REQUIRE(server_endpoint.use_count() == 0);

                server_endpoint = net.endpoint(
                        server_addr, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);
            }

            SECTION("0-RTT successful with retry - new server listening with same TLS creds, but different static secret")
            {
                // This case is a bit weird: because of the changed static secret, the server
                // rejects the initial crypto (and the initial datagram/stream data) and issues a
                // retry.  The client then updates and retries, *and* then succeeds with a 0RTT.
                // (Technically it's now 1RTT, but 0RTT early data is still saving a round trip
                // because if, after the retry, 0RTT still fails there would need to be another RTT,
                // making the whole thing 2RTT overall).
                //
                // This can only really happen if both the server static secret changes *and* the
                // client reuses the same endpoint for which it had previously received path
                // validation tokens.
                expected_rtt = 2;

                net.close(std::move(server_endpoint));
                REQUIRE(server_endpoint.use_count() == 0);

                server_endpoint =
                        net.endpoint(server_addr, server_established, opt::enable_datagrams{} /*, no static secret!*/);
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);
            }

            SECTION("0-RTT rejected - TLS restarted")
            {
                // Restart the server listener with a *different* tls creds so that it is
                // regenerates its key, and thus can't accept 0rtt connections it issued before it
                // restarted.
                expected_rtt = 2;

                net.close(std::move(server_endpoint));
                REQUIRE(server_endpoint.use_count() == 0);

                server_tls = defaults::tls_creds_from_ed_keys().second;
                server_tls->enable_inbound_0rtt();

                server_endpoint = net.endpoint(
                        server_addr, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);
            }

            SECTION("0-RTT rejected with retry - TLS restarted")
            {
                // This is a sort of worse case for 0RTT: the server changes its static secret,
                // which invalids path tokens, issues a retry, then the retry rejects 0RTT and it
                // has to do 1-RTT, so there ends up (including the retry) being 2 rtt for
                // establishing and then the data finally comes in 3rtt.  (This isn't really
                // specific to 0-rtt though; a retry with 1-rtt would cause the same).
                //
                // This can only really happen if both the server static secret changes *and* the
                // client reuses the same endpoint for which it had previously received path
                // validation tokens.
                expected_rtt = 3;

                net.close(std::move(server_endpoint));
                REQUIRE(server_endpoint.use_count() == 0);

                server_tls = defaults::tls_creds_from_ed_keys().second;
                server_tls->enable_inbound_0rtt();

                server_endpoint =
                        net.endpoint(server_addr, server_established, opt::enable_datagrams{} /*, no static secret!*/);
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);
            }

#if 0
            // This case currently does not work: ngtcp2 does not notice the incompatible transport
            // param on the server side, signals an acceptance of early data, but then the client
            // sees that acceptance, compares transport param values, and drops the connection with
            // NGTCP2_ERR_PROTO.  See ngtcp issue #1551.
            SECTION("0-RTT rejected - server transport param changed")
            {
                // Restart the server listener with a *different* tls creds so that it is
                // regenerates its key, and thus can't accept 0rtt connections it issued before it
                // restarted.
                expected_rtt = 2;

                net.close(std::move(server_endpoint));
                REQUIRE(server_endpoint.use_count() == 0);

                server_endpoint = net.endpoint(
                        server_addr, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb, opt::max_streams{24});
            }
#endif
        }

        auto SIMULATED_RTT = 20ms;
        auto RTT_BUFFER = 15ms;
#if !defined(__linux__)
        // Apple's OS just sucks
        SIMULATED_RTT *= 5;
        RTT_BUFFER *= 5;

#elif !defined(__x86_64__)
        // Linux ARM running on overloaded Pis can need a lot more
        SIMULATED_RTT *= 10;
        RTT_BUFFER *= 10;
#endif

#ifndef NDEBUG
        // Debug builds can take way longer, especially with trace logging
        SIMULATED_RTT *= 4;
        RTT_BUFFER *= 4;
#endif

        delayer->delay = SIMULATED_RTT / 2;

        std::promise<std::chrono::nanoseconds> stream_response_time, dgram_response_time;
        auto started = std::chrono::steady_clock::now();
        auto client_ci = client_endpoint->connect(
                client_remote,
                client_tls,
                client_established,
                [&](Stream&, std::span<const std::byte>) {
                    stream_response_time.set_value(std::chrono::steady_clock::now() - started);
                },
                [&](dgram_interface&, std::span<const std::byte>) {
                    dgram_response_time.set_value(std::chrono::steady_clock::now() - started);
                });

        auto s = client_ci->open_stream<Stream>();
        s->send("hello"s);
        client_ci->send_datagram("42"s);

        require_future(client_established_prom.get_future());
        require_future(server_established_prom.get_future());

        auto dgram_fut = dgram_response_time.get_future();
        require_future(dgram_fut, SIMULATED_RTT * (expected_rtt + 2));
        auto dgram_time = dgram_fut.get();
        CHECK(dgram_time > expected_rtt * SIMULATED_RTT - RTT_BUFFER);
        CHECK(dgram_time < expected_rtt * SIMULATED_RTT + RTT_BUFFER);

        auto stream_fut = stream_response_time.get_future();
        require_future(stream_fut, SIMULATED_RTT * (expected_rtt + 2));
        auto stream_time = stream_fut.get();
        CHECK(stream_time > expected_rtt * SIMULATED_RTT - RTT_BUFFER);
        CHECK(stream_time < expected_rtt * SIMULATED_RTT + RTT_BUFFER);
    }

}  //  namespace oxen::quic::test
