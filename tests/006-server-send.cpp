#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("006: Server successfully sending stream data", "[006][server][send]")
    {
        logger_config();

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_stream;

        std::promise<bool> server_promise, client_promise, stream_promise;
        std::future<bool> server_future = server_promise.get_future(), 
                client_future = client_promise.get_future(),
                stream_future = stream_promise.get_future();

        stream_open_callback stream_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
            server_stream = s.shared_from_this();
            stream_promise.set_value(true);
            return 0;
        };

        stream_data_callback server_stream_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");
            server_promise.set_value(true);
            data_check += 1;
        };

        stream_data_callback client_stream_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling client stream data callback... data received... incrementing counter...");
            client_promise.set_value(true);
            data_check += 1;
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, stream_open_cb, server_stream_data_cb));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_stream_data_cb);

        auto client_stream = conn_interface->get_new_stream();
        client_stream->send(msg);

        REQUIRE(stream_future.get());

        server_stream->send(msg);

        REQUIRE(client_future.get());
        REQUIRE(server_future.get());
        REQUIRE(data_check == 2);
        test_net.close();
    };
}  // namespace oxen::quic::test
