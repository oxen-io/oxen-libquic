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
        bool_waiter<connection_established_callback> client_established;
        Network test_net{};

        opt::max_streams max_streams{8};

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, max_streams));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established.func());
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        REQUIRE(client_established.wait_ready());
        REQUIRE(conn_interface->get_max_streams() == max_streams.stream_count);
    };

    TEST_CASE("004 - Multiple pending streams: streams available", "[004][streams][pending][config]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> data_promise;
        std::future<bool> data_future = data_promise.get_future();
        opt::max_streams max_streams{8};

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            data_promise.set_value(true);
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, max_streams, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        auto client_stream = conn_interface->get_new_stream();
        client_stream->send(msg);

        REQUIRE(data_future.get());
        REQUIRE(conn_interface->get_streams_available() == max_streams.stream_count - 1);
    };

    TEST_CASE("004 - Multiple pending streams: different remote settings", "[004][streams][pending][config]")
    {
        bool_waiter<connection_established_callback> client_established;
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> data_promise;
        std::future<bool> data_future = data_promise.get_future();
        opt::max_streams server_config{10}, client_config{8};

        std::shared_ptr<connection_interface> server_ci;

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            data_promise.set_value(true);
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_config, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established.func());
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_config);

        REQUIRE(client_established.wait_ready());

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
        bool_waiter<connection_established_callback> client_established;
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<int> index{0};
        std::atomic<int> data_check{0};
        int n_streams = 12;
        int n_sends = n_streams + 2, n_recvs = n_streams + 1;

        opt::max_streams max_streams{n_streams - 4};  // 8
        std::vector<std::shared_ptr<Stream>> streams{size_t(n_streams)};

        opt::local_addr server_local{};
        opt::local_addr client_local{};

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

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, max_streams, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established.func());
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, max_streams);

        REQUIRE(client_established.wait_ready());

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

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, standard_server_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

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

        stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e) {
            return std::make_shared<ServerStream>(c, e, std::move(client_promise));
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e) {
            return std::make_shared<ClientStream>(c, e, std::move(server_promise));
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_constructor));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(msg));

        REQUIRE(server_future.get());
    };
}  // namespace oxen::quic::test
