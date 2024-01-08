#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <stdexcept>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("004 - Multiple pending streams: max stream count", "[004][streams][pending][config]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        opt::max_streams max_streams{8};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, max_streams));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        REQUIRE(client_established.wait());
        REQUIRE(conn_interface->get_max_streams() == max_streams.stream_count);
    };

    TEST_CASE("004 - Multiple pending streams: streams available", "[004][streams][pending][config]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> data_promise;
        std::future<bool> data_future = data_promise.get_future();
        opt::max_streams max_streams{8};

        Address server_local{};
        Address client_local{};

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            data_promise.set_value(true);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, max_streams, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        auto client_stream = conn_interface->open_stream();
        client_stream->send(msg);

        REQUIRE(data_future.get());
        REQUIRE(conn_interface->get_streams_available() == max_streams.stream_count - 1);
    };

    TEST_CASE("004 - Multiple pending streams: different remote settings", "[004][streams][pending][config]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> data_promise;
        std::future<bool> data_future = data_promise.get_future();
        opt::max_streams server_config{10}, client_config{8};

        std::shared_ptr<connection_interface> server_ci;

        Address server_local{};
        Address client_local{};

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            data_promise.set_value(true);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_config, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_config);

        REQUIRE(client_established.wait());

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        // some transport parameters are set after handshake is completed; querying the client connection too
        // quickly will return a streams_available of 0
        std::this_thread::sleep_for(5ms);

        REQUIRE(client_ci->get_max_streams() == client_config.stream_count);
        REQUIRE(server_ci->get_streams_available() == client_config.stream_count);
        REQUIRE(client_ci->get_streams_available() == server_config.stream_count);
        REQUIRE(server_ci->get_max_streams() == server_config.stream_count);

        auto client_stream = client_ci->open_stream();
        client_stream->send(msg);

        REQUIRE(data_future.get());

        REQUIRE(client_ci->get_max_streams() == client_config.stream_count);
        REQUIRE(server_ci->get_streams_available() == client_config.stream_count);
        REQUIRE(client_ci->get_streams_available() == server_config.stream_count - 1);
        REQUIRE(server_ci->get_max_streams() == server_config.stream_count);
    };

    TEST_CASE("004 - Multiple pending streams: Execution", "[004][streams][pending][execute]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<size_t> index{0};
        std::atomic<size_t> data_check{0};
        size_t n_streams = 12, n_sends = n_streams + 2, n_recvs = n_streams + 1;

        opt::max_streams max_streams{n_streams - 4};  // 8
        std::vector<std::shared_ptr<Stream>> streams{n_streams};

        Address server_local{};
        Address client_local{};

        std::vector<std::promise<bool>> send_promises{n_sends}, receive_promises{n_recvs};
        std::vector<std::future<bool>> send_futures{n_sends}, receive_futures{n_recvs};

        for (size_t i = 0; i < n_recvs; ++i)
        {
            send_futures[i] = send_promises[i].get_future();
            receive_futures[i] = receive_promises[i].get_future();
        }
        send_futures[n_sends - 1] = send_promises[n_sends - 1].get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");

            try
            {
                data_check += 1;
                receive_promises.at(index++).set_value(true);
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, max_streams, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        REQUIRE(client_established.wait());

        for (size_t i = 0; i < n_streams; ++i)
        {
            streams[i] = conn_interface->open_stream();
            streams[i]->send(msg);
            send_promises[i].set_value(true);
        }

        // 2) check the first 8
        for (size_t i = 0; i < n_streams - 4; ++i)
            REQUIRE(receive_futures[i].get());

        // 3) close 5 streams
        for (size_t i = 0; i < 5; ++i)
            streams[i]->close();

        // 4) check the last 4
        for (size_t i = n_streams - 4; i < n_streams; ++i)
            REQUIRE(receive_futures[i].get());

        // 5) open 2 more streams and send
        for (int i = 0; i < 2; ++i)
        {
            streams[i] = conn_interface->open_stream();
            streams[i]->send(msg);
            // set send promise
            send_promises[i + n_streams].set_value(true);
        }

        // 6) check final stream received data
        REQUIRE(receive_futures[n_streams].get());

        // 7) verify
        for (auto& f : send_futures)
            REQUIRE(f.get());

        auto* conn = client_endpoint->get_conn(conn_interface->scid());

        REQUIRE(conn);

        std::promise<bool> p;
        std::future<bool> f = p.get_future();

        client_endpoint->call([&]() {
            REQUIRE(conn->num_pending() == 1);
            p.set_value(true);
        });

        REQUIRE(f.get());

        REQUIRE(data_check == n_recvs);
    };

    struct ClientStream : public Stream
    {
        std::promise<bool> p;

        ClientStream(Connection& _c, Endpoint& _e, std::promise<bool> _p) : Stream{_c, _e}, p{std::move(_p)} {}

        void receive(bstring_view) override
        {
            log::debug(log_cat, "Calling custom stream data callback... data received...");
            p.set_value(true);
        }
    };

    struct ServerStream : public Stream
    {
        std::promise<bool> p;

        ServerStream(Connection& _c, Endpoint& _e, std::promise<bool> _p) : Stream{_c, _e}, p{std::move(_p)} {}

        void receive(bstring_view) override
        {
            log::debug(log_cat, "Calling custom stream data callback... data received...");
            p.set_value(true);
        }
    };

    TEST_CASE("004 - Subclassing quic::stream, custom to standard", "[004][customstream][cross]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> ss_p, sc_p, cs_p, cc_p;
        std::future<bool> ss_f = ss_p.get_future(), sc_f = sc_p.get_future(), cs_f = cs_p.get_future(),
                          cc_f = cc_p.get_future();

        stream_data_callback standard_server_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling standard stream data callback... data received...");
            REQUIRE(msg == dat);
            ss_p.set_value(true);
            s.send(msg);
        };

        stream_data_callback standard_client_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling standard stream data callback... data received...");
            REQUIRE(msg == dat);
            cs_p.set_value(true);
            s.send(msg);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, standard_server_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, standard_client_cb);

        auto client_stream = conn_interface->open_stream<ClientStream>(std::move(cc_p));

        REQUIRE_NOTHROW(client_stream->send(msg));

        REQUIRE(ss_f.get());
        REQUIRE(cc_f.get());

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        auto server_stream = server_ci->open_stream<ServerStream>(std::move(sc_p));

        REQUIRE_NOTHROW(server_stream->send(msg));

        REQUIRE(cs_f.get());
        REQUIRE(sc_f.get());
    };

    TEST_CASE("004 - Subclassing quic::stream, custom to custom", "[004][customstream][subclass]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> server_promise, client_promise;
        std::future<bool> server_future = server_promise.get_future();

        stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            return e.make_shared<ServerStream>(c, e, std::move(client_promise));
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            return e.make_shared<ClientStream>(c, e, std::move(server_promise));
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(msg));

        REQUIRE(server_future.get());
    };

    struct CustomStream : public Stream
    {
        std::promise<std::string> p;

        CustomStream(Connection& _c, Endpoint& _e, std::promise<std::string> _p) : Stream{_c, _e}, p{std::move(_p)} {}

        void receive(bstring_view m) override
        {
            log::info(log_cat, "Custom stream received data:\n{}", buffer_printer{m});
            p.set_value(std::string{convert_sv<char>(m)});
        }
    };

    struct CustomStreamA : public CustomStream
    {
        using CustomStream::CustomStream;
    };

    struct CustomStreamB : public CustomStream
    {
        using CustomStream::CustomStream;
    };

    struct CustomStreamC : public CustomStream
    {
        using CustomStream::CustomStream;
    };

    TEST_CASE("004 - Subclassing quic::stream, sequential stream queuing", "[004][customstream][sequential][server]")
    {
        Network test_net{};

        std::promise<std::string> sp1, sp2, sp3, sp4, cp1, cp2, cp3;
        std::future<std::string> sf1 = sp1.get_future(), sf2 = sp2.get_future(), sf3 = sp3.get_future(),
                                 sf4 = sp4.get_future(), cf1 = cp1.get_future(), cf2 = cp2.get_future(),
                                 cf3 = cp3.get_future();

        std::shared_ptr<CustomStreamA> server_a, client_a;
        std::shared_ptr<CustomStreamB> server_b, client_b;
        std::shared_ptr<CustomStreamC> server_c, client_c;
        std::shared_ptr<Stream> server_d, client_d;

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        stream_data_callback server_generic_data_cb = [&](Stream&, bstring_view m) {
            log::debug(log_cat, "Server generic data callback called");
            sp4.set_value(std::string{convert_sv<char>(m)});
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::atomic<int> server_stream_ctor_count = 0;
        int expected_server_stream_ctor_count = 0;

        Address server_local{};
        Address client_local{};

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;
        std::shared_ptr<connection_interface> client_ci;

        // SECTION("Stream logic using queue_incoming_stream in connection open callback")
        // {
        //     auto server_open_all_cb = callback_waiter{[&](connection_interface& ci) {
        //         log::info(bp_cat, "Server queuing Custom Stream A!");
        //         server_a = ci.queue_incoming_stream<CustomStreamA>(std::move(sp1));
        //         log::info(bp_cat, "Server queuing Custom Stream B!");
        //         server_b = ci.queue_incoming_stream<CustomStreamB>(std::move(sp2));
        //         log::info(bp_cat, "Server queuing Custom Stream C!");
        //         server_c = ci.queue_incoming_stream<CustomStreamC>(std::move(sp3));
        //         log::info(bp_cat, "Server queueing default stream D");
        //         server_d = ci.queue_incoming_stream();
        //     }};

        //     server_endpoint = test_net.endpoint(server_local, server_open_all_cb, server_closed);
        //     REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_generic_data_cb));

        //     RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        //     client_endpoint = test_net.endpoint(client_local, client_established);
        //     client_ci = client_endpoint->connect(client_remote, client_tls);

        //     REQUIRE(client_established.wait());
        //     CHECK(server_open_all_cb.wait());
        // }

        // SECTION("Stream logic using stream constructor callback")
        // {
        //     // Our stream constructor callback should get invoked for every stream as, in this
        //     // section, we do everything through the constructor callback.
        //     expected_server_stream_ctor_count = 4;

        //     stream_constructor_callback server_constructor =
        //             [&](Connection& c, Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
        //         server_stream_ctor_count++;
        //         if (id)
        //         {
        //             switch (*id)
        //             {
        //                 case 0:
        //                     log::info(bp_cat, "Server opening Custom Stream A!");
        //                     return e.make_shared<CustomStreamA>(c, e, std::move(sp1));
        //                 case 4:
        //                     log::info(bp_cat, "Server opening Custom Stream B!");
        //                     return e.make_shared<CustomStreamB>(c, e, std::move(sp2));
        //                 case 8:
        //                     log::info(bp_cat, "Server opening Custom Stream C!");
        //                     return e.make_shared<CustomStreamC>(c, e, std::move(sp3));
        //             }
        //         }
        //         return nullptr;
        //     };

        //     server_endpoint = test_net.endpoint(server_local, server_closed);
        //     REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor, server_generic_data_cb));

        //     RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        //     client_endpoint = test_net.endpoint(client_local, client_established);
        //     client_ci = client_endpoint->connect(client_remote, client_tls);

        //     REQUIRE(client_established.wait());
        // }

        SECTION("Stream logic using mixed queue/stream constructor callbacks")
        {
            // Our stream constructor callback should get invoked streams 4 and 8 (which we handle)
            // and 12 (which we decline to fall back to a default stream), but not 0, because 0 gets
            // created earlier via a queue_incoming_stream<CustomStreamA> call and so shouldn't end
            // up in the callback.
            expected_server_stream_ctor_count = 3;

            stream_constructor_callback server_constructor =
                    [&](Connection& c, Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
                server_stream_ctor_count++;
                if (id)
                {
                    switch (*id)
                    {
                        case 4:
                            log::info(bp_cat, "Server opening Custom Stream B!");
                            return e.make_shared<CustomStreamB>(c, e, std::move(sp2));
                        case 8:
                            log::info(bp_cat, "Server opening Custom Stream C!");
                            return e.make_shared<CustomStreamC>(c, e, std::move(sp3));
                    }
                }
                return nullptr;
            };

            auto server_open_cb = callback_waiter{[&](connection_interface& ci) {
                log::info(bp_cat, "Server queuing Custom Stream A!");
                server_a = ci.queue_incoming_stream<CustomStreamA>(std::move(sp1));
            }};

            server_endpoint = test_net.endpoint(server_local, server_closed);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor, server_open_cb, server_generic_data_cb));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            client_endpoint = test_net.endpoint(client_local, client_established);
            client_ci = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());
        }

        log::info(bp_cat, "Client opening Custom Stream A!");
        client_a = client_ci->open_stream<CustomStreamA>(std::move(cp1));
        REQUIRE_NOTHROW(client_a->send("Stream A!"_bs));
        CHECK(require_future(sf1) == "Stream A!");

        log::info(bp_cat, "Client opening Custom Stream B!");
        client_b = client_ci->open_stream<CustomStreamB>(std::move(cp2));
        REQUIRE_NOTHROW(client_b->send("Stream B!"_bs));
        CHECK(require_future(sf2) == "Stream B!");

        log::info(bp_cat, "Client opening Custom Stream C!");
        client_c = client_ci->open_stream<CustomStreamC>(std::move(cp3));
        REQUIRE_NOTHROW(client_c->send("Stream C!"_bs));
        CHECK(require_future(sf3) == "Stream C!");

        client_d = client_ci->open_stream();
        client_d->send("Stream d!"_bs);
        CHECK(require_future(sf4) == "Stream d!");

        client_ci->close_connection();
        REQUIRE(server_closed.wait());

        CHECK(expected_server_stream_ctor_count == server_stream_ctor_count.load());
    };

    TEST_CASE("004 - subclass retrieval", "[004][customstream][get_stream]")
    {
        Network test_net{};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls);

        auto client_endpoint = test_net.endpoint(client_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        auto a = client_ci->open_stream<CustomStreamA>(std::promise<std::string>{});
        auto b = client_ci->open_stream<CustomStreamB>(std::promise<std::string>{});
        auto c = client_ci->open_stream<CustomStreamC>(std::promise<std::string>{});
        auto d = client_ci->open_stream();

        // On slower setups, a small amount of time is needed to finish initializing all the streams
        std::this_thread::sleep_for(5ms);

        CHECK(client_ci->get_stream(0) == a);
        CHECK(client_ci->get_stream(4) == b);
        CHECK(client_ci->get_stream(8) == c);
        CHECK(client_ci->get_stream(12) == d);

        CHECK(client_ci->get_stream<CustomStreamA>(0) == a);
        CHECK(client_ci->get_stream<CustomStreamB>(4) == b);
        CHECK(client_ci->get_stream<CustomStreamC>(8) == c);

        CHECK(client_ci->get_stream<CustomStream>(0) == a);
        CHECK(client_ci->get_stream<CustomStream>(4) == b);
        CHECK(client_ci->get_stream<CustomStream>(8) == c);

        CHECK(client_ci->maybe_stream<CustomStreamA>(0) == a);
        CHECK(client_ci->maybe_stream<CustomStreamB>(4) == b);
        CHECK(client_ci->maybe_stream<CustomStreamC>(8) == c);

        CHECK(client_ci->maybe_stream<CustomStream>(0) == a);
        CHECK(client_ci->maybe_stream<CustomStream>(4) == b);
        CHECK(client_ci->maybe_stream<CustomStream>(8) == c);

        CHECK_FALSE(client_ci->maybe_stream(16));
        CHECK_FALSE(client_ci->maybe_stream<CustomStreamC>(16));

        CHECK_THROWS_AS(client_ci->get_stream<CustomStreamB>(16), std::out_of_range);
        CHECK_THROWS_AS(client_ci->get_stream(16), std::out_of_range);

        CHECK_THROWS_AS(client_ci->get_stream<CustomStreamB>(0), std::invalid_argument);
        CHECK_THROWS_AS(client_ci->get_stream<CustomStreamA>(4), std::invalid_argument);
        CHECK_THROWS_AS(client_ci->get_stream<CustomStreamB>(8), std::invalid_argument);
        CHECK_THROWS_AS(client_ci->maybe_stream<CustomStreamB>(0), std::invalid_argument);
        CHECK_THROWS_AS(client_ci->maybe_stream<CustomStreamC>(4), std::invalid_argument);
        CHECK_THROWS_AS(client_ci->maybe_stream<CustomStream>(12), std::invalid_argument);
    }

    TEST_CASE("004 - Subclassing quic::stream, sequential client stream queuing", "[004][customstream][sequential][client]")
    {
        Network test_net{};

        std::mutex mut;
        std::map<int64_t, int> server_seen;

        std::promise<std::string> cp1, cp2, cp3, cp4;
        std::future<std::string> cf1 = cp1.get_future(), cf2 = cp2.get_future(), cf3 = cp3.get_future(),
                                 cf4 = cp4.get_future();

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        stream_data_callback server_data_cb = [&](Stream& s, bstring_view) {
            std::lock_guard lock{mut};
            server_seen[s.stream_id()]++;
            s.send("🤔 {}"_format(s.stream_id()));
        };

        Address server_local{};
        Address client_local{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, server_closed);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        std::atomic<int> client_stream_ctor_count = 0;

        auto client_stream_ctor = [&](Connection& c, Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
            int count = ++client_stream_ctor_count;

            // We won't have an id yet because we create all the streams
            CHECK_FALSE(id);

            // But we can just count to see how many times we've been called:
            switch (count)
            {
                case 1:
                    log::info(bp_cat, "Server opening Custom Stream A!");
                    return e.make_shared<CustomStreamA>(c, e, std::move(cp1));
                case 2:
                    log::info(bp_cat, "Server opening Custom Stream C!");
                    return e.make_shared<CustomStreamC>(c, e, std::move(cp3));
            }
            return nullptr;
        };

        auto client_generic_data_cb = [&](Stream&, bstring_view data) {
            log::debug(log_cat, "Client generic data callback called");
            cp4.set_value(std::string{convert_sv<char>(data)});
        };

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_generic_data_cb, client_stream_ctor);

        REQUIRE(client_established.wait());

        auto s1 = client_ci->open_stream();
        CHECK(client_stream_ctor_count.load() == 1);
        REQUIRE(std::dynamic_pointer_cast<CustomStreamA>(s1));

        auto s2 = client_ci->open_stream<CustomStreamB>(std::move(cp2));
        CHECK(client_stream_ctor_count.load() == 1);  // should *not* have hit the stream constructor
        static_assert(std::is_same_v<decltype(s2), std::shared_ptr<CustomStreamB>>);

        auto s3 = client_ci->open_stream();
        CHECK(client_stream_ctor_count.load() == 2);
        REQUIRE(std::dynamic_pointer_cast<CustomStreamA>(s1));

        auto s4 = client_ci->open_stream();
        CHECK(client_stream_ctor_count.load() == 3);
        // This should be a generic Stream, not a CustomStreamA/B/C:
        REQUIRE_FALSE(std::dynamic_pointer_cast<CustomStream>(s4));

        s1->send("Stream A!"_bs);
        s2->send("Stream B!"_bs);
        s3->send("Stream C!"_bs);
        s4->send("Stream D!"_bs);

        CHECK(require_future(cf1) == "🤔 0");
        CHECK(require_future(cf2) == "🤔 4");
        CHECK(require_future(cf3) == "🤔 8");
        CHECK(require_future(cf4) == "🤔 12");

        {
            std::lock_guard lock{mut};
            CHECK(server_seen == std::map<int64_t, int>{{0, 1}, {4, 1}, {8, 1}, {12, 1}});
        }

        client_ci->close_connection();
        REQUIRE(server_closed.wait());
    };

    TEST_CASE("004 - BTRequestStream, server stream extraction", "[004][server][extraction]")
    {
        Network test_net{};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::shared_ptr<BTRequestStream> server_extracted, client_extracted;
        std::shared_ptr<connection_interface> server_ci;

        auto server_handler = callback_waiter{[&](message msg) { REQUIRE(msg.stream() == server_extracted); }};

        auto client_handler = callback_waiter{[&](message msg) { REQUIRE(msg.stream() == client_extracted); }};

        auto client_established = callback_waiter{[&](connection_interface& ci) {
            client_extracted = ci.open_stream<BTRequestStream>();
            client_extracted->register_handler("test_endpoint"s, client_handler);
        }};

        stream_constructor_callback server_constructor =
                [&](Connection& c, Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
            if (id)
            {
                if (*id == 0)
                {
                    server_extracted = e.make_shared<BTRequestStream>(c, e);
                    server_extracted->register_handler("test_endpoint"s, server_handler);
                    return server_extracted;
                }
                else
                {
                    return e.make_shared<Stream>(c, e);
                }
            }

            throw std::runtime_error{"We need ID's!"};
        };

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_constructor);

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        std::shared_ptr<BTRequestStream> client_bt = client_ci->maybe_stream<BTRequestStream>(0);
        REQUIRE(client_extracted->stream_id() == client_bt->stream_id());
        REQUIRE(client_extracted == client_bt);

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        std::shared_ptr<BTRequestStream> early_access = server_ci->maybe_stream<BTRequestStream>(0);
        REQUIRE_FALSE(early_access);

        client_extracted->command("test_endpoint"s, "hi"s);
        REQUIRE(server_handler.wait());

        std::shared_ptr<BTRequestStream> server_bt = server_ci->maybe_stream<BTRequestStream>(0);
        REQUIRE(server_bt);
        REQUIRE(server_extracted->stream_id() == 0);
        REQUIRE(server_extracted->stream_id() == server_bt->stream_id());
        REQUIRE(server_extracted == server_bt);

        server_extracted->command("test_endpoint"s, "hi"s);
        REQUIRE(client_handler.wait());
    };

    TEST_CASE("004 - BTRequestStream, server extracts queued streams", "[004][server][queue]")
    {
        Network test_net{};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::shared_ptr<BTRequestStream> server_bt, client_bt;
        std::shared_ptr<connection_interface> server_ci;

        auto server_handler = callback_waiter{[&](message msg) { REQUIRE(msg.stream() == server_bt); }};

        auto client_handler = callback_waiter{[&](message msg) { REQUIRE(msg.stream() == client_bt); }};

        auto server_established = callback_waiter{[&](connection_interface& ci) {
            server_bt = ci.queue_incoming_stream<BTRequestStream>();
            server_bt->register_handler("test_endpoint"s, server_handler);
        }};

        auto client_established = callback_waiter{[&](connection_interface&) {}};

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_established);

        auto client_endpoint = test_net.endpoint(client_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_established);

        REQUIRE(client_established.wait());
        REQUIRE(server_established.wait());

        client_bt = client_ci->open_stream<BTRequestStream>();
        client_bt->register_handler("test_endpoint"s, client_handler);
        REQUIRE(client_bt->stream_id() == 0);

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        std::shared_ptr<BTRequestStream> server_extracted = server_ci->maybe_stream<BTRequestStream>(0);
        REQUIRE(server_bt->stream_id() == 0);
        REQUIRE(server_extracted);
        REQUIRE(server_bt == server_extracted);

        client_bt->command("test_endpoint"s, "hi"s);
        REQUIRE(server_handler.wait());

        server_bt->command("test_endpoint"s, "hi"s);
        REQUIRE(client_handler.wait());
    };

    TEST_CASE("004 - BTRequestStream, send queue functionality", "[004][sendqueue]")
    {
        Network test_net{};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::shared_ptr<BTRequestStream> server_bt, client_bt;
        std::shared_ptr<connection_interface> server_ci, client_ci;

        int n_reqs{5};
        std::atomic<int> server_counter{0};

        auto server_handler = [&](message msg) {
            REQUIRE(msg.body() == TEST_BODY);
            server_counter += 1;

            log::debug(log_cat, "Server received request {} of {}", server_counter.load(), n_reqs);

            if (server_counter == n_reqs)
            {
                log::debug(log_cat, "Server responding to client with new request");
                server_bt->command(TEST_ENDPOINT, TEST_BODY);
            }
        };

        auto client_handler = callback_waiter{[](message msg) {
            log::debug(log_cat, "Client received server request!");
            REQUIRE(msg.body() == TEST_BODY);
        }};

        server_tls->set_key_verify_callback([&](const ustring_view&, const ustring_view&) {
            // In order to test the queueing ability of streams, we need to attempt to send things
            // from the client side PRIOR to connection completion. Using the TLS verification callback
            // is the improper and hacky way to do this, but will function fine for the purposes of this
            // test case. Do not actually do this!

            client_bt = client_ci->open_stream<BTRequestStream>();
            client_bt->register_command(TEST_ENDPOINT, client_handler);

            for (int i = 0; i < n_reqs; ++i)
                client_bt->command(TEST_ENDPOINT, TEST_BODY);

            REQUIRE(client_bt->num_pending() == (size_t)n_reqs);

            return true;
        });

        auto server_established = callback_waiter{[&](connection_interface& ci) {
            server_bt = ci.queue_incoming_stream<BTRequestStream>();
            server_bt->register_command(TEST_ENDPOINT, server_handler);
        }};

        auto client_established = callback_waiter{[&](connection_interface&) {}};

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_established);

        auto client_endpoint = test_net.endpoint(client_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        client_ci = client_endpoint->connect(client_remote, client_tls, client_established);

        REQUIRE(client_established.wait());
        REQUIRE(server_established.wait());
        REQUIRE(client_handler.wait());
    };

}  // namespace oxen::quic::test
