#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("006 - Server streams: Direct creation and transmission", "[006][server][streams][send][execute]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_stream;

        std::promise<bool> server_promise, client_promise, stream_promise;
        std::future<bool> server_future = server_promise.get_future(), client_future = client_promise.get_future(),
                          stream_future = stream_promise.get_future();

        stream_open_callback server_io_open_cb = [&](IOChannel& s) {
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
            server_stream = s.get_stream();
            stream_promise.set_value(true);
            return 0;
        };

        stream_data_callback server_io_data_cb = [&](IOChannel&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
            server_promise.set_value(true);
        };

        stream_data_callback client_io_data_cb = [&](IOChannel&, bstring_view) {
            log::debug(log_cat, "Calling client stream data callback... data received... incrementing counter...");
            data_check += 1;
            client_promise.set_value(true);
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_io_open_cb, server_io_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_io_data_cb);

        auto client_stream = conn_interface->get_new_stream();
        client_stream->send(msg);

        REQUIRE(stream_future.get());

        server_stream->send(msg);

        REQUIRE(client_future.get());
        REQUIRE(server_future.get());
        REQUIRE(data_check == 2);
    };

    TEST_CASE("006 - Server streams: Remote initiation, server send", "[006][server][streams][send][execute]")
    {
        Network test_net{};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;
        auto response = "okay okay i get it already"_bsv;

        std::atomic<int> ci{0}, si{0};
        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_extracted_stream, client_extracted_stream;
        std::shared_ptr<connection_interface> server_ci;

        std::vector<std::promise<bool>> server_promises{3}, client_promises{3};
        std::vector<std::future<bool>> server_futures{3}, client_futures{3};

        for (int i = 0; i < 3; ++i)
        {
            server_futures[i] = server_promises[i].get_future();
            client_futures[i] = client_promises[i].get_future();
        }

        stream_open_callback server_io_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
            server_extracted_stream = s.get_stream();
            try
            {
                server_promises.at(si).set_value(true);
                ++si;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
            return 0;
        };

        stream_open_callback client_io_open_cb = [&](Stream& s) {
            log::debug(log_cat, "Calling client stream open callback... stream opened...");
            client_extracted_stream = s.get_stream();
            try
            {
                client_promises.at(ci).set_value(true);
                ++ci;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
            return 0;
        };

        stream_data_callback server_io_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
            try
            {
                server_promises.at(si).set_value(true);
                ++si;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        stream_data_callback client_io_data_cb = [&](Stream&, bstring_view) {
            log::debug(log_cat, "Calling client stream data callback... data received... incrementing counter...");
            data_check += 1;
            try
            {
                client_promises.at(ci).set_value(true);
                ++ci;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_io_data_cb, server_io_open_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_io_data_cb, client_io_open_cb);

        auto client_stream = client_ci->get_new_stream();
        client_stream->send(msg);

        REQUIRE(server_futures[0].get());
        REQUIRE(server_futures[1].get());

        server_extracted_stream->send(response);
        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        auto server_stream = server_ci->get_new_stream();
        server_stream->send(msg);

        for (auto& c : client_futures)
            REQUIRE(c.get());

        client_extracted_stream->send(response);

        REQUIRE(server_futures[2].get());
        REQUIRE(data_check == 4);
    };
}  // namespace oxen::quic::test
