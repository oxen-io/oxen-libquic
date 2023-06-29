#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002: Simple client to server transmission", "[002][simple]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of client to server transmission...");

        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;
        bstring_view capture;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();
        std::promise<bool> s_init;
        std::future<bool> s_future = s_init.get_future();
 
        stream_data_callback_t server_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            capture = dat;
            d_promise.set_value(true);
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

        auto server_endpoint = test_net.endpoint(server_local);
        s_init.set_value(server_endpoint->listen(server_tls, server_data_cb));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();
        client_stream->send(msg);

        REQUIRE(s_future.get());
        REQUIRE(d_future.get());
        REQUIRE(msg == capture);
        test_net.close();
    };
}  // namespace oxen::quic::test
