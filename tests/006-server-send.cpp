#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("006 - Server streams: Direct creation and transmission", "[006][server][streams][send][execute]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsp;

        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_stream;

        std::promise<void> server_promise, client_promise, stream_promise;
        std::future<void> server_future = server_promise.get_future(), client_future = client_promise.get_future(),
                          stream_future = stream_promise.get_future();

        stream_open_callback server_io_open_cb = [&](IOChannel& s) {
            log::debug(test_cat, "Calling server stream open callback... stream opened...");
            server_stream = s.get_stream();
            stream_promise.set_value();
            return 0;
        };

        stream_data_callback server_io_data_cb = [&](IOChannel&, bspan) {
            log::debug(test_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
            server_promise.set_value();
        };

        stream_data_callback client_io_data_cb = [&](IOChannel&, bspan) {
            log::debug(test_cat, "Calling client stream data callback... data received... incrementing counter...");
            data_check += 1;
            client_promise.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_io_open_cb, server_io_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_io_data_cb);

        auto client_stream = conn_interface->open_stream();
        client_stream->send(msg, nullptr);

        require_future(stream_future);

        server_stream->send(msg, nullptr);

        require_future(client_future);
        require_future(server_future);
        REQUIRE(data_check == 2);
    }

    TEST_CASE("006 - Server streams: Remote initiation, server send", "[006][server][streams][send][execute]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsp;
        constexpr auto response = "okay okay i get it already"_bsp;

        std::atomic<int> ci{0}, si{0};
        std::atomic<int> data_check{0};

        std::shared_ptr<Stream> server_extracted_stream, client_extracted_stream;
        std::shared_ptr<connection_interface> server_ci;

        std::vector<std::promise<void>> server_promises{3}, client_promises{3};
        std::vector<std::future<void>> server_futures{3}, client_futures{3};

        for (int i = 0; i < 3; ++i)
        {
            server_futures[i] = server_promises[i].get_future();
            client_futures[i] = client_promises[i].get_future();
        }

        stream_open_callback server_io_open_cb = [&](Stream& s) {
            log::debug(test_cat, "Calling server stream open callback... stream opened...");
            server_extracted_stream = s.get_stream();
            try
            {
                server_promises.at(si).set_value();
                ++si;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
            return 0;
        };

        stream_open_callback client_io_open_cb = [&](Stream& s) {
            log::debug(test_cat, "Calling client stream open callback... stream opened...");
            client_extracted_stream = s.get_stream();
            try
            {
                client_promises.at(ci).set_value();
                ++ci;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
            return 0;
        };

        stream_data_callback server_io_data_cb = [&](Stream&, bspan) {
            log::debug(test_cat, "Calling server stream data callback... data received... incrementing counter...");
            data_check += 1;
            try
            {
                server_promises.at(si).set_value();
                ++si;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        stream_data_callback client_io_data_cb = [&](Stream&, bspan) {
            log::debug(test_cat, "Calling client stream data callback... data received... incrementing counter...");
            data_check += 1;
            try
            {
                client_promises.at(ci).set_value();
                ++ci;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_io_data_cb, server_io_open_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto client_ci = client_endpoint->connect(client_remote, client_tls, client_io_data_cb, client_io_open_cb);

        auto client_stream = client_ci->open_stream();
        client_stream->send(msg, nullptr);

        require_future(server_futures[0]);
        require_future(server_futures[1]);

        server_extracted_stream->send(response, nullptr);
        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();
        auto server_stream = server_ci->open_stream();
        server_stream->send(msg, nullptr);

        for (auto& c : client_futures)
            require_future(c);

        client_extracted_stream->send(response, nullptr);

        require_future(server_futures[2]);
        REQUIRE(data_check == 4);
    }
}  // namespace oxen::quic::test
