#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("001 - Handshaking: Types", "[001][handshake][tls][types]")
    {
        SECTION("TLS Credentials")
        {
            REQUIRE_NOTHROW(GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s));
            REQUIRE_THROWS(GNUTLSCreds::make(""s, ""s, ""s));
        };

        SECTION("Address objects")
        {
            opt::local_addr empty_addr{};
            opt::local_addr good_addr{"127.0.0.1", 4400};

            REQUIRE_THROWS(opt::local_addr{"127.001", 4400});
            REQUIRE_THROWS(opt::local_addr{""s, 0});
            REQUIRE(empty_addr.is_set());
            REQUIRE(empty_addr == opt::local_addr{"::", 0});
            REQUIRE(good_addr.is_set());
        };

        SECTION("Endpoint object creation")
        {
            Network test_net{};
            opt::local_addr default_addr{};

            auto ep = test_net.endpoint(default_addr);

            REQUIRE(ep->local_addr() == default_addr.to_string());
            test_net.close();
        };

        SECTION("Endpoint::listen()")
        {
            Network test_net{};
            opt::local_addr default_addr{}, local_addr{"127.0.0.1"s, 4401};
            auto local_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            auto ep_notls = test_net.endpoint(default_addr);
            auto ep_tls = test_net.endpoint(local_addr);

            REQUIRE_THROWS(ep_notls->listen());
            REQUIRE_NOTHROW(ep_tls->listen(local_tls));
            test_net.close();
        };

        SECTION("Endpoint::connect()")
        {
            Network test_net{};
            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            opt::local_addr server_local{"127.0.0.1"s, 5500};
            opt::local_addr client_local{"127.0.0.1"s, 4402};
            opt::remote_addr client_remote{"127.0.0.1"s, 5500};

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE(server_endpoint->listen(server_tls));

            auto client_endpoint = test_net.endpoint(client_local);
            // no client TLS passed
            REQUIRE_THROWS(client_endpoint->connect(client_remote));
            test_net.close();
        };
    };

    TEST_CASE("001 - Handshaking: Execution", "[001][handshake][tls][execute]")
    {
        SECTION("Unsuccessful TLS handshake - No server TLS credentials")
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

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            opt::local_addr server_local{"127.0.0.1"s, 5501};
            opt::local_addr client_local{"127.0.0.1"s, 4403};
            opt::remote_addr client_remote{"127.0.0.1"s, 5501};

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_THROWS(server_endpoint->listen());

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(tls_future.valid());
            test_net.close();
        };

        SECTION("Successful TLS handshake")
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

            auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
            auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
            client_tls->set_client_tls_policy(outbound_tls_cb);

            opt::local_addr server_local{"127.0.0.1"s, 5502};
            opt::local_addr client_local{"127.0.0.1"s, 4404};
            opt::remote_addr client_remote{"127.0.0.1"s, 5502};

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE(server_endpoint->listen(server_tls));

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(tls_future.get());
            test_net.close();
        };
    };
}  // namespace oxen::quic::test
