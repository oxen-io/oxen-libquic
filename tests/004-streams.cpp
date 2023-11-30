#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
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

        auto client_stream = conn_interface->get_new_stream();
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

        auto client_stream = client_ci->get_new_stream();
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

        std::atomic<int> index{0};
        std::atomic<int> data_check{0};
        int n_streams = 12;
        int n_sends = n_streams + 2, n_recvs = n_streams + 1;

        opt::max_streams max_streams{n_streams - 4};  // 8
        std::vector<std::shared_ptr<Stream>> streams{size_t(n_streams)};

        Address server_local{};
        Address client_local{};

        std::vector<std::promise<bool>> send_promises{size_t(n_sends)}, receive_promises{size_t(n_recvs)};
        std::vector<std::future<bool>> send_futures{size_t(n_sends)}, receive_futures{size_t(n_recvs)};

        for (int i = 0; i < n_recvs; ++i)
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
                receive_promises.at(index).set_value(true);
                ++index;
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

        for (int i = 0; i < n_streams; ++i)
        {
            streams[i] = conn_interface->get_new_stream();
            streams[i]->send(msg);
            send_promises[i].set_value(true);
        }

        // 2) check the first 8
        for (int i = 0; i < n_streams - 4; ++i)
            REQUIRE(receive_futures[i].get());

        // 3) close 5 streams
        for (int i = 0; i < 5; ++i)
            streams[i]->close();

        // 4) check the last 4
        for (int i = n_streams - 4; i < n_streams; ++i)
            REQUIRE(receive_futures[i].get());

        // 5) open 2 more streams and send
        for (int i = 0; i < 2; ++i)
        {
            streams[i] = conn_interface->get_new_stream();
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

        auto client_stream = conn_interface->get_new_stream<ClientStream>(std::move(cc_p));

        REQUIRE_NOTHROW(client_stream->send(msg));

        REQUIRE(ss_f.get());
        REQUIRE(cc_f.get());

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        auto server_stream = server_ci->get_new_stream<ServerStream>(std::move(sc_p));

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
            return std::make_shared<ServerStream>(c, e, std::move(client_promise));
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            return std::make_shared<ClientStream>(c, e, std::move(server_promise));
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(msg));

        REQUIRE(server_future.get());
    };

    struct CustomStream : public Stream
    {
        std::promise<bool> p;
        const bstring msg = "Stream!"_bs;

        CustomStream(Connection& _c, Endpoint& _e, std::promise<bool> _p) : Stream{_c, _e}, p{std::move(_p)} {}

        void receive(bstring_view m) override
        {
            log::info(log_cat, "Custom stream received data. Identity: \n{}", buffer_printer{msg});
            REQUIRE(m == msg);
            p.set_value(true);
        }
    };

    struct CustomStreamA : public CustomStream
    {
        const bstring msg = "Stream A!"_bs;

        using CustomStream::CustomStream;

        void receive(bstring_view m) override
        {
            log::info(log_cat, "Custom stream received data. Identity: \n{}", buffer_printer{msg});
            REQUIRE(m == msg);
            p.set_value(true);
        }
    };

    struct CustomStreamB : public CustomStream
    {
        const bstring msg = "Stream B!"_bs;

        using CustomStream::CustomStream;

        void receive(bstring_view m) override
        {
            log::info(log_cat, "Custom stream received data. Identity: \n{}", buffer_printer{msg});
            REQUIRE(m == msg);
            p.set_value(true);
        }
    };

    struct CustomStreamC : public CustomStream
    {
        const bstring msg = "Stream C!"_bs;

        using CustomStream::CustomStream;

        void receive(bstring_view m) override
        {
            log::info(log_cat, "Custom stream received data. Identity: \n{}", buffer_printer{msg});
            REQUIRE(m == msg);
            p.set_value(true);
        }
    };

    TEST_CASE("004 - Subclassing quic::stream, sequential stream opening", "[004][customstream][sequential]")
    {
        Network test_net{};

        std::promise<bool> sp1, sp2, sp3, cp1, cp2, cp3;
        std::future<bool> sf1 = sp1.get_future(), sf2 = sp2.get_future(), sf3 = sp3.get_future(), cf1 = cp1.get_future(),
                          cf2 = cp2.get_future(), cf3 = cp3.get_future();

        std::shared_ptr<CustomStreamA> server_a, client_a;
        std::shared_ptr<CustomStreamB> server_b, client_b;
        std::shared_ptr<CustomStreamC> server_c, client_c;

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        SECTION("Stream logic using connection open callback")
        {
            auto server_open_cb = callback_waiter{[&](connection_interface& ci) {
                log::info(bp_cat, "Server queuing Custom Stream A!");
                server_a = ci.queue_stream<CustomStreamA>(std::move(sp1));
                log::info(bp_cat, "Server queuing Custom Stream B!");
                server_b = ci.queue_stream<CustomStreamB>(std::move(sp2));
                log::info(bp_cat, "Server queuing Custom Stream C!");
                server_c = ci.queue_stream<CustomStreamC>(std::move(sp3));
            }};

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            Address server_local{};
            Address client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_open_cb, server_closed);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);
            auto client_ci = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());
            CHECK(server_open_cb.is_ready());

            log::info(bp_cat, "Client opening Custom Stream A!");
            client_a = client_ci->get_new_stream<CustomStreamA>(std::move(cp1));
            REQUIRE_NOTHROW(client_a->send("Stream A!"_bs));
            REQUIRE(sf1.get());

            log::info(bp_cat, "Client opening Custom Stream B!");
            client_b = client_ci->get_new_stream<CustomStreamB>(std::move(cp2));
            REQUIRE_NOTHROW(client_b->send("Stream B!"_bs));
            REQUIRE(sf2.get());

            log::info(bp_cat, "Client opening Custom Stream C!");
            client_c = client_ci->get_new_stream<CustomStreamC>(std::move(cp3));
            REQUIRE_NOTHROW(client_c->send("Stream C!"_bs));
            REQUIRE(sf3.get());

            client_ci->close_connection();
            REQUIRE(server_closed.wait());
        }

        SECTION("Stream logic using stream constructor callback")
        {
            stream_constructor_callback server_constructor =
                    [&](Connection& c, Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
                if (id)
                {
                    switch (*id)
                    {
                        case 0:
                            log::info(bp_cat, "Server opening Custom Stream A!");
                            return std::make_shared<CustomStreamA>(c, e, std::move(sp1));
                        case 4:
                            log::info(bp_cat, "Server opening Custom Stream B!");
                            return std::make_shared<CustomStreamB>(c, e, std::move(sp2));
                        case 8:
                            log::info(bp_cat, "Server opening Custom Stream C!");
                            return std::make_shared<CustomStreamC>(c, e, std::move(sp3));
                        default:
                            return std::make_shared<Stream>(c, e);
                    }
                }
                return std::make_shared<Stream>(c, e);
            };

            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

            Address server_local{};
            Address client_local{};

            auto server_endpoint = test_net.endpoint(server_local, server_closed);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);
            auto client_ci = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

            log::info(bp_cat, "Client opening Custom Stream A!");
            client_a = client_ci->get_new_stream<CustomStreamA>(std::move(cp1));
            REQUIRE_NOTHROW(client_a->send("Stream A!"_bs));
            REQUIRE(sf1.get());

            log::info(bp_cat, "Client opening Custom Stream B!");
            client_b = client_ci->get_new_stream<CustomStreamB>(std::move(cp2));
            REQUIRE_NOTHROW(client_b->send("Stream B!"_bs));
            REQUIRE(sf2.get());

            log::info(bp_cat, "Client opening Custom Stream C!");
            client_c = client_ci->get_new_stream<CustomStreamC>(std::move(cp3));
            REQUIRE_NOTHROW(client_c->send("Stream C!"_bs));
            REQUIRE(sf3.get());

            client_ci->close_connection();
            REQUIRE(server_closed.wait());
        }
    };

}  // namespace oxen::quic::test
