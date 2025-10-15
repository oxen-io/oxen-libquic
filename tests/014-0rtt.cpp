#include "unit_test.hpp"

#include <gnutls/crypto.h>

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
        auto server_established = [&server_established_prom](Connection&) { server_established_prom.set_value(); };
        std::promise<void> client_established_prom;
        auto client_established = [&client_established_prom](Connection&) { client_established_prom.set_value(); };

        Loop loop;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();
        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        Address server_local{LOCALHOST, 0};
        Address client_local{LOCALHOST, 0};

        auto delayer = packet_delayer::make(0ms);  // no delay initially, but we'll ramp it up later
        auto client_endpoint = Endpoint::endpoint(loop, client_local, opt::enable_datagrams{}, *delayer);
        delayer->init(client_endpoint);

        std::vector<unsigned char> server_secret;
        server_secret.resize(32);
        gnutls_rnd(GNUTLS_RND_RANDOM, server_secret.data(), server_secret.size());

        auto server_endpoint = Endpoint::endpoint(
                loop, server_local, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});

        auto server_stream_cb = [](Stream& s, std::span<const std::byte> data) {
            log::debug(log_cat, "server stream got {} stream bytes", data.size());
            s.send("OK"s);
        };
        auto server_dgram_cb = [](datagram dg) {
            log::debug(log_cat, "server received {}B datagram", dg.data.size());
            dg.datagrams.send("OK"s);
        };
        server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);

        auto server_addr = server_endpoint->local();

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, server_addr};

        // How many latency we expect until we get a response to our stream/datagram.  1 for 0-RTT
        // (i.e. 0-RTT means no additional establishing latency), 2 for 1-RTT (i.e. 1-RTT to
        // establish and then one to send and receive).
        int expected_rtt = 2;

        SECTION("0-RTT not available")
        {
            // Without a prior connection there will be no 0-RTT data for us to try with, so we
            // should just do a plain 1-RTT without even trying early data.
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

                REQUIRE(server_endpoint.use_count() == 1);
                server_endpoint.reset();

                server_endpoint = Endpoint::endpoint(
                        loop, server_addr, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});
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

                REQUIRE(server_endpoint.use_count() == 1);
                server_endpoint.reset();

                server_endpoint = Endpoint::endpoint(
                        loop, server_addr, server_established, opt::enable_datagrams{} /*, no static secret!*/);
                server_endpoint->listen(server_tls, server_stream_cb, server_dgram_cb);
            }

            SECTION("0-RTT rejected - TLS restarted")
            {
                // Restart the server listener with a *different* tls creds so that it is
                // regenerates its key, and thus can't accept 0rtt connections it issued before it
                // restarted.
                expected_rtt = 2;

                REQUIRE(server_endpoint.use_count() == 1);
                server_endpoint.reset();

                server_tls = defaults::tls_creds_from_ed_keys().second;
                server_tls->enable_inbound_0rtt();

                server_endpoint = Endpoint::endpoint(
                        loop, server_addr, server_established, opt::enable_datagrams{}, opt::static_secret{server_secret});
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

                REQUIRE(server_endpoint.use_count() == 1);
                server_endpoint.reset();

                server_tls = defaults::tls_creds_from_ed_keys().second;
                server_tls->enable_inbound_0rtt();

                server_endpoint = Endpoint::endpoint(
                        loop, server_addr, server_established, opt::enable_datagrams{} /*, no static secret!*/);
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

                REQUIRE(server_endpoint.use_count() == 1);
                server_endpoint.reset();

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
                [&](datagram) { dgram_response_time.set_value(std::chrono::steady_clock::now() - started); });

        auto s = client_ci->open_stream<Stream>();
        s->send("hello"s);
        client_ci->datagrams()->send("42"s);

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

    TEST_CASE("014 - 0-RTT early data conn established callback", "[014][0rtt][conn-established]")
    {
        // This test makes sure that the connection established connection gets called for early
        // stream data *before* the stream construction happens.

        if (disable_0rtt)
            SKIP("0-RTT tests not enabled for this test iteration!");

        Loop loop;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        server_tls->require_client_keys(nullptr);

        Address server_local{LOCALHOST, 0};
        Address client_local{LOCALHOST, 0};

        std::promise<ConnectionID> s_est_prom;
        std::optional<bool> s_est_first;
        std::promise<void> s_str_prom;
        std::string estcb_alpn, estcb_remote_pk;

        auto server_endpoint = Endpoint::endpoint(loop, server_local, opt::inbound_alpns{"foo41", "foo42", "foo43"});
        server_endpoint->listen(
                server_tls,
                [&s_est_prom, &s_est_first, &estcb_alpn, &estcb_remote_pk](Connection& c) {
                    if (!s_est_first)
                        s_est_first = true;
                    estcb_alpn = c.selected_alpn();
                    estcb_remote_pk = oxenc::to_hex(view(c.remote_key()));
                    s_est_prom.set_value(c.reference_id());
                },
                [&s_est_first, &s_str_prom](Stream&) {
                    if (!s_est_first)
                        s_est_first = false;
                    s_str_prom.set_value();
                    return 0;
                }

        );

        auto client_endpoint = Endpoint::endpoint(loop, client_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, server_endpoint->local()};
        std::promise<void> c_est_prom;
        auto conn =
                client_endpoint->connect(client_remote, client_tls, opt::outbound_alpn("foo42"), [&c_est_prom](Connection&) {
                    c_est_prom.set_value();
                });

        require_future(c_est_prom.get_future());
        auto s_connid_fut = s_est_prom.get_future();
        require_future(s_connid_fut);

        CHECK(conn->selected_alpn() == "foo42");
        CHECK(oxenc::to_hex(conn->remote_key()) == oxenc::to_hex(defaults::SERVER_PUBKEY));

        auto sconn = server_endpoint->get_conn(s_connid_fut.get());
        CHECK(sconn->selected_alpn() == "foo42");
        CHECK(oxenc::to_hex(sconn->remote_key()) == oxenc::to_hex(defaults::CLIENT_PUBKEY));
        CHECK(estcb_alpn == "foo42");
        CHECK(estcb_remote_pk == oxenc::to_hex(defaults::CLIENT_PUBKEY));

        // TLS tickets can arrive just after the handshake confirmed packet, so add a tiny
        // extra wait to allow for them to arrive.
        std::this_thread::sleep_for(5ms);

        // Now we close and reopen the connection, as it should now have 0-RTT data.
        conn->close_connection();
        conn.reset();

        std::this_thread::sleep_for(5ms);

        s_est_prom = {};
        c_est_prom = {};
        s_est_first.reset();
        estcb_alpn = "";
        estcb_remote_pk = "";

        conn = client_endpoint->connect(client_remote, client_tls, opt::outbound_alpn("foo42"), [&c_est_prom](Connection&) {
            c_est_prom.set_value();
        });

        auto str = conn->open_stream();
        str->send("hello");

        require_future(c_est_prom.get_future());
        s_connid_fut = s_est_prom.get_future();
        require_future(s_connid_fut);

        CHECK(conn->selected_alpn() == "foo42");
        CHECK(oxenc::to_hex(conn->remote_key()) == oxenc::to_hex(defaults::SERVER_PUBKEY));

        sconn = server_endpoint->get_conn(s_connid_fut.get());
        CHECK(sconn->selected_alpn() == "foo42");
        CHECK(oxenc::to_hex(sconn->remote_key()) == oxenc::to_hex(defaults::CLIENT_PUBKEY));
        require_future(s_str_prom.get_future());

        CHECK(s_est_first.has_value());
        // The server's conn establish should get fired before the stream:
        CHECK(*s_est_first);
        CHECK(estcb_alpn == "foo42");
        CHECK(estcb_remote_pk == oxenc::to_hex(defaults::CLIENT_PUBKEY));
    }

    TEST_CASE("014 - 0-RTT with key verification", "[014][0rtt][key-verify]")
    {
        if (disable_0rtt)
            SKIP("0-RTT tests not enabled for this test iteration!");

        Loop loop;

        std::atomic<bool> bad_foo = false;
        std::shared_ptr<GNUTLSCreds> client_tls, server_tls;
        std::promise<std::vector<unsigned char>> key_prom;
        bool expect_pubkey = true, expect_key_prom = true;
        SECTION("With client keys required")
        {
            std::tie(client_tls, server_tls) = defaults::tls_creds_from_ed_keys();
            server_tls->require_client_keys(
                    [&key_prom, &bad_foo](std::span<const unsigned char> key, std::string_view alpn) {
                        key_prom.set_value(std::vector<unsigned char>{key.begin(), key.end()});
                        if (alpn != "foo42")
                            bad_foo = true;
                        return true;
                    });
        }
        SECTION("With optional client keys provided")
        {
            std::tie(client_tls, server_tls) = defaults::tls_creds_from_ed_keys();
            server_tls->request_client_keys(
                    [&key_prom, &bad_foo](std::span<const unsigned char> key, std::string_view alpn) {
                        key_prom.set_value(std::vector<unsigned char>{key.begin(), key.end()});
                        if (alpn != "foo42")
                            bad_foo = true;
                        return true;
                    });
        }
        SECTION("With optional client keys omitted")
        {
            server_tls = GNUTLSCreds::make_from_ed_keys(defaults::SERVER_SEED, defaults::SERVER_PUBKEY);
            server_tls->request_client_keys(
                    [&key_prom, &bad_foo](std::span<const unsigned char> key, std::string_view alpn) {
                        key_prom.set_value(std::vector<unsigned char>{key.begin(), key.end()});
                        if (alpn != "foo42")
                            bad_foo = true;
                        return true;
                    });
            client_tls = GNUTLSCreds::make_unauthenticated();
            expect_pubkey = false;
        }
        SECTION("Without client keys requested")
        {
            server_tls = GNUTLSCreds::make_from_ed_keys(defaults::SERVER_SEED, defaults::SERVER_PUBKEY);
            client_tls = GNUTLSCreds::make_unauthenticated();
            expect_pubkey = false;
            expect_key_prom = false;
        }

        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        Address server_local{LOCALHOST, 0};
        Address client_local{LOCALHOST, 0};

        std::promise<ConnectionID> s_est_prom;
        auto server_endpoint = Endpoint::endpoint(loop, server_local, opt::inbound_alpns{"foo41", "foo42", "foo43"});

        server_endpoint->listen(server_tls, [&s_est_prom](Connection& c) { s_est_prom.set_value(c.reference_id()); });

        auto client_endpoint = Endpoint::endpoint(loop, client_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, server_endpoint->local()};
        std::promise<void> c_est_prom;
        auto conn =
                client_endpoint->connect(client_remote, client_tls, opt::outbound_alpn("foo42"), [&c_est_prom](Connection&) {
                    c_est_prom.set_value();
                });

        require_future(c_est_prom.get_future());
        auto s_connid_fut = s_est_prom.get_future();
        require_future(s_connid_fut);
        auto key_fut = key_prom.get_future();
        // The key verify callback should only get called if the client actually has a key to
        // provide:
        if (expect_key_prom)
            require_future(key_fut);
        else
            CHECK(key_fut.wait_for(0s) == std::future_status::timeout);

        REQUIRE(conn->selected_alpn() == "foo42");
        REQUIRE(oxenc::to_hex(conn->remote_key()) == oxenc::to_hex(defaults::SERVER_PUBKEY));

        auto sconn = server_endpoint->get_conn(s_connid_fut.get());
        REQUIRE(sconn->selected_alpn() == "foo42");
        if (expect_key_prom)
        {
            if (expect_pubkey)
                REQUIRE(oxenc::to_hex(view(key_fut.get())) == oxenc::to_hex(defaults::CLIENT_PUBKEY));
            else
                REQUIRE(oxenc::to_hex(view(key_fut.get())) == "");
        }
        if (expect_pubkey)
            REQUIRE(oxenc::to_hex(sconn->remote_key()) == oxenc::to_hex(defaults::CLIENT_PUBKEY));
        else
            REQUIRE(oxenc::to_hex(sconn->remote_key()) == "");

        // TLS tickets can arrive just after the handshake confirmed packet, so add a tiny
        // extra wait to allow for them to arrive.
        std::this_thread::sleep_for(5ms);

        // Now we close and reopen the connection, as it should now have 0-RTT data.
        conn->close_connection();
        conn.reset();

        std::this_thread::sleep_for(5ms);

        s_est_prom = {};
        c_est_prom = {};
        key_prom = {};
        conn = client_endpoint->connect(client_remote, client_tls, opt::outbound_alpn("foo42"), [&c_est_prom](Connection&) {
            c_est_prom.set_value();
        });

        require_future(c_est_prom.get_future());

        s_connid_fut = s_est_prom.get_future();
        require_future(s_connid_fut);
        // The key verify callback does *not* get called for 0-RTT:
        CHECK(key_prom.get_future().wait_for(0s) == std::future_status::timeout);

        REQUIRE(conn->selected_alpn() == "foo42");
        REQUIRE(oxenc::to_hex(conn->remote_key()) == oxenc::to_hex(defaults::SERVER_PUBKEY));

        sconn = server_endpoint->get_conn(s_connid_fut.get());
        REQUIRE(sconn->selected_alpn() == "foo42");
        if (expect_pubkey)
            REQUIRE(oxenc::to_hex(sconn->remote_key()) == oxenc::to_hex(defaults::CLIENT_PUBKEY));
        else
            REQUIRE(oxenc::to_hex(sconn->remote_key()) == "");

        REQUIRE(!bad_foo.load());
    }

    TEST_CASE("014 - Send empty initial 0RTT stream data", "[014][0rtt][streams][empty]")
    {
        // This is the same test as the opt::stream_notify test in 004-streams.cpp, except here
        // applied to a 0-RTT stream: when creating a new stream the stream is not opened on the
        // remote until stream data arrives.  QUIC explicitly allows a 0-length stream frame to be
        // used to serve as a stream open notification when no data is available.
        //
        // This tests that same test but with:
        // - early data
        // - rejected early data

        if (disable_0rtt)
            SKIP("0-RTT tests not enabled for this test iteration!");

        Loop loop;

        std::shared_ptr<GNUTLSCreds> client_tls, server_tls;
        std::tie(client_tls, server_tls) = defaults::tls_creds_from_ed_keys();
        server_tls->require_client_keys(nullptr);
        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        Address server_local{LOCALHOST, 0};
        Address client_local{LOCALHOST, 0};

        std::promise<ConnectionID> s_est_prom;
        auto server_endpoint = Endpoint::endpoint(loop, server_local, opt::inbound_alpn("foo"));

        std::shared_ptr<Stream> incoming_stream;

        std::shared_ptr<quic::Stream> s_str;
        server_endpoint->listen(server_tls, [&s_est_prom, &incoming_stream](Connection& c) {
            incoming_stream = c.queue_incoming_stream();
            s_est_prom.set_value(c.reference_id());
        });

        auto client_endpoint = Endpoint::endpoint(loop, client_local);
        std::promise<void> c_est_prom;
        auto conn = client_endpoint->connect(
                RemoteAddress{defaults::SERVER_PUBKEY, server_endpoint->local()},
                client_tls,
                opt::outbound_alpn("foo"),
                [&c_est_prom](Connection&) { c_est_prom.set_value(); });
        conn->open_stream(opt::stream_notify);

        auto s_est_fut = s_est_prom.get_future();
        require_future(s_est_fut);

        REQUIRE(incoming_stream->is_ready());
        REQUIRE(incoming_stream->stream_id() == 0);

        auto c_est_fut = c_est_prom.get_future();
        require_future(c_est_fut);

        // At this point we just made a 1-RTT connection on a 0-RTT enabled server, so this is
        // likely no different than what the 004 test accomplishes (except with 0rtt flipped on but
        // not actually used yet):

        incoming_stream.reset();

        // TLS tickets can arrive just after the handshake confirmed packet, so add a tiny
        // extra wait to allow for them to arrive.
        std::this_thread::sleep_for(5ms);

        // Now we close and reopen the connection, as it should now have 0-RTT data.
        conn->close_connection();
        conn.reset();

        std::this_thread::sleep_for(5ms);

        SECTION("With 0-RTT early data accepted")
        {
            // Do nothing
        }
        SECTION("With 0-RTT early data rejected")
        {
            // Restart the server with a new creds object so that there will be a new 0RTT key and
            // early data will be rejected
            auto addr = server_endpoint->local();
            server_endpoint.reset();

            std::tie(std::ignore, server_tls) = defaults::tls_creds_from_ed_keys();
            server_tls->require_client_keys(nullptr);
            server_tls->enable_inbound_0rtt();

            server_endpoint = Endpoint::endpoint(loop, addr, opt::inbound_alpn("foo"));
            server_endpoint->listen(server_tls, [&s_est_prom, &incoming_stream](Connection& c) {
                incoming_stream = c.queue_incoming_stream();
                s_est_prom.set_value(c.reference_id());
            });
        }

        s_est_prom = {};
        s_est_fut = s_est_prom.get_future();
        c_est_prom = {};
        c_est_fut = c_est_prom.get_future();

        loop.call_get([&] {
            conn = client_endpoint->connect(
                    RemoteAddress{defaults::SERVER_PUBKEY, server_endpoint->local()},
                    client_tls,
                    opt::outbound_alpn("foo"),
                    [&c_est_prom](Connection&) { c_est_prom.set_value(); });

            std::promise<size_t> received;
            auto cstream = conn->open_stream(opt::stream_notify);
        });

        require_future(s_est_fut);
        require_future(c_est_fut);
        REQUIRE(incoming_stream->is_ready());
        REQUIRE(incoming_stream->stream_id() == 0);
    }

}  //  namespace oxen::quic::test
