#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <stdexcept>
#include <thread>

#include "quic/connection.hpp"
#include "quic/opt.hpp"
#include "quic/types.hpp"
#include "quic/utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("007 - Datagram support: Types", "[007][datagrams][types]")
    {
        SECTION("opt::enable_datagrams default construction behaviors")
        {
            Network test_net{};

            opt::enable_datagrams default_dgram{},   // packet_splitting = false
                    split_dgram{Splitting::ACTIVE};  // packet_splitting = true, policy = ::GREEDY

            opt::local_addr local_a{}, local_b{}, local_c{}, local_d{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            // datagrams = false, packet_splitting = false, splitting_policy = ::NONE
            auto vanilla_ep = test_net.endpoint(local_a);
            REQUIRE_NOTHROW(vanilla_ep->listen(server_tls));

            REQUIRE_FALSE(vanilla_ep->datagrams_enabled());
            REQUIRE_FALSE(vanilla_ep->packet_splitting_enabled());
            REQUIRE(vanilla_ep->splitting_policy() == Splitting::NONE);

            // datagrams = true, packet_splitting = true, splitting_policy = ::NONE
            auto default_ep = test_net.endpoint(local_b, default_dgram);
            REQUIRE_NOTHROW(default_ep->listen(server_tls));

            REQUIRE(default_ep->datagrams_enabled());
            REQUIRE_FALSE(default_ep->packet_splitting_enabled());
            REQUIRE(default_ep->splitting_policy() == Splitting::NONE);

            // datagrams = true, packet_splitting = true
            auto splitting_ep = test_net.endpoint(local_d, split_dgram);
            REQUIRE_NOTHROW(splitting_ep->listen(server_tls));

            REQUIRE(splitting_ep->datagrams_enabled());
            REQUIRE(splitting_ep->packet_splitting_enabled());
            REQUIRE(splitting_ep->splitting_policy() == Splitting::ACTIVE);

            test_net.close();
        };

        SECTION("Query max datagram size from datagram-disabled endpoint")
        {
            Network test_net{};

            std::promise<bool> tls;
            std::future<bool> tls_future = tls.get_future();

            gnutls_callback outbound_tls_cb =
                    [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                        log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                        tls.set_value(true);
                        return 0;
                    };

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());
            REQUIRE_FALSE(conn_interface->datagrams_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
            REQUIRE(conn_interface->get_max_datagram_size() == 0);

            test_net.close();
        };

        SECTION("Query max datagram size from default datagram-enabled endpoints")
        {
            Network test_net{};

            std::promise<bool> tls;
            std::future<bool> tls_future = tls.get_future();

            gnutls_callback outbound_tls_cb =
                    [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                        log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                        tls.set_value(true);
                        return 0;
                    };

            opt::enable_datagrams default_gram{};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            auto server_endpoint = test_net.endpoint(server_local, default_gram);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, default_gram);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());
            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);

            REQUIRE(conn_interface->get_max_datagram_size() < MAX_PMTUD_UDP_PAYLOAD);

            test_net.close();
        };

        SECTION("Query max datagram size from split-datagram enabled endpoint")
        {
            Network test_net{};

            std::promise<bool> tls;
            std::future<bool> tls_future = tls.get_future();

            gnutls_callback outbound_tls_cb =
                    [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                        log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                        tls.set_value(true);
                        return 0;
                    };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};
            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, split_dgram);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());
            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE(conn_interface->packet_splitting_enabled());

            std::this_thread::sleep_for(5ms);

            REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

            test_net.close();
        };
    };

    TEST_CASE("007 - Datagram support: Execute, No Splitting Policy", "[007][datagrams][execute][nosplit]")
    {
        SECTION("Simple datagram transmission")
        {
            Network test_net{};
            auto msg = "hello from the other siiiii-iiiiide"_bsv;

            std::promise<bool> tls_promise, data_promise;
            std::future<bool> tls_future = tls_promise.get_future(), data_future = data_promise.get_future();

            gnutls_callback outbound_tls_cb =
                    [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                        log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                        tls_promise.set_value(true);
                        return 0;
                    };

            dgram_data_callback recv_dgram_cb = [&](bstring_view) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                data_promise.set_value(true);
            };

            opt::enable_datagrams default_gram{};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            auto server_endpoint = test_net.endpoint(server_local, default_gram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, default_gram);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());

            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
            REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

            conn_interface->send_datagram(msg);

            std::this_thread::sleep_for(500ms);

            REQUIRE(data_future.get());

            test_net.close();
        };
    };

    TEST_CASE("007 - Datagram support: Execute, Packet Splitting Enabled", "[007][datagrams][execute][split]")
    {
        SECTION("Simple datagram transmission")
        {
            Network test_net{};
            std::string data{};
            char v = 0;

            while (data.size() < 2000)
                data += v++;

            std::atomic<int> index{0};
            std::atomic<int> data_counter{0};
            std::vector<std::promise<bool>> data_promises{2};
            std::vector<std::future<bool>> data_futures{2};

            for (int i = 0; i < 2; ++i)
                data_futures[i] = data_promises[i].get_future();

            std::promise<bool> tls_promise;
            std::future<bool> tls_future = tls_promise.get_future();

            gnutls_callback outbound_tls_cb =
                    [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                        log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                        tls_promise.set_value(true);
                        return 0;
                    };

            dgram_data_callback recv_dgram_cb = [&](bstring_view) {
                log::debug(log_cat, "Calling endpoint receive datagram callback... data received...");

                try
                {
                    data_counter += 1;
                    data_promises.at(index).set_value(true);
                    index += 1;
                }
                catch (std::exception& e)
                {
                    throw std::runtime_error(e.what());
                }
            };

            opt::enable_datagrams split_dgram{Splitting::ACTIVE};

            opt::local_addr server_local{};
            opt::local_addr client_local{};

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

            auto client = test_net.endpoint(client_local, split_dgram);
            auto conn_interface = client->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());

            REQUIRE(server_endpoint->datagrams_enabled());
            REQUIRE(client->datagrams_enabled());

            REQUIRE(conn_interface->datagrams_enabled());
            REQUIRE(conn_interface->packet_splitting_enabled());
            REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

            conn_interface->send_datagram(std::move(data));

            std::this_thread::sleep_for(500ms);

            for (auto& f : data_futures)
                REQUIRE(f.get());

            REQUIRE(data_counter == 2);
            test_net.close();
        };
    };
}  // namespace oxen::quic::test
