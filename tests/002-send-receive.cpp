#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][execute]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;
        bstring_view bad_msg;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));
        REQUIRE_THROWS(client_stream->send(bad_msg));

        REQUIRE(d_future.get());
    };

<<<<<<< HEAD
    TEST_CASE("002 - Simple client to server transmission", "[002][simple][bidirectional]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;
        bstring_view bad_msg;

        std::vector<std::promise<bool>> d_promises{2};
        std::vector<std::future<bool>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value(true);
            index += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_a_local{}, server_b_local{};
        opt::local_addr client_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_a_local);
        REQUIRE(server_endpoint_b->listen(server_tls, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint_b->local().port()};
        opt::remote_addr server_remote{"127.0.0.1"s, server_endpoint_a->local().port()};

        auto server_ci = server_endpoint_b->connect(server_remote, server_tls);
        auto server_stream = server_ci->get_new_stream();

        server_stream->send(good_msg);

        REQUIRE(d_futures[0].get());

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));
        REQUIRE_THROWS(client_stream->send(bad_msg));

        REQUIRE(d_futures[1].get());
    };

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][2x2]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::vector<std::promise<bool>> d_promises{2};
        std::vector<std::future<bool>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promises.at(index).set_value(true);
            index += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

        opt::local_addr server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_a_local);
        REQUIRE(server_endpoint_b->listen(server_tls, server_data_cb));

        opt::remote_addr server_remote_a{"127.0.0.1"s, server_endpoint_a->local().port()};
        opt::remote_addr server_remote_b{"127.0.0.1"s, server_endpoint_b->local().port()};

        auto server_a_ci = server_endpoint_b->connect(server_remote_a, server_tls);
        auto server_a_stream = server_a_ci->get_new_stream();

        server_a_stream->send(good_msg);

        REQUIRE(d_futures[0].get());

        auto server_b_ci = server_endpoint_a->connect(server_remote_b, server_tls);

        auto server_b_stream = server_b_ci->get_new_stream();

        server_b_stream->send(good_msg);

        REQUIRE(d_futures[1].get());
    };

    TEST_CASE("002 - BParser Testing", "[002][bparser]")
=======
    /* TEST_CASE("002 - BParser Testing", "[002][bparser]")
>>>>>>> 678a9e5 (stashing)
    {
        Network test_net{};

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::this_thread::sleep_for(250ms);

        auto client_bp = std::make_shared<bparser>();
        auto server_bp = std::make_shared<bparser>();

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        auto server_stream = server_ci->get_new_stream(*server_bp, *server_bp);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream(*client_bp, *client_bp);

        client_bp->command("test_endpoint"s, "test_request_body"s);

        std::this_thread::sleep_for(250ms);
<<<<<<< HEAD
    };

=======
    }; */
>>>>>>> 678a9e5 (stashing)
}  // namespace oxen::quic::test
