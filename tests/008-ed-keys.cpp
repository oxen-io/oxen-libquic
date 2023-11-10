#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("008 - Ed Keys: Types", "[008][edkeys][types]")
    {
        auto client_seed = oxenc::from_hex("468e7ed2cd914ca44568e7189245c7b8e5488404fc88a4019c73b51d9dbc48a5");
        auto client_pubkey = oxenc::from_hex("626136fe40c8860ee5bdc57fd9f15a03ef6777bb9237c18fc4d7ef2aacfe4f88");

        auto server_seed = oxenc::from_hex("fefbb50cdd4cde3be0ae75042c44ff42b026def4fd6be4fb1dc6e81ea0480c9b");
        auto server_pubkey = oxenc::from_hex("d580d5c68937095ea997f6a88f07a86cdd26dfa0d7d268e80ea9bbb5f3ca0304");

        SECTION("Bad Input")
        {
            REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys("", ""));
            REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys("notavalidkey", client_pubkey));
            REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(client_seed, "notavalidkey"));

            // Both of these should error in gnutls (which I then throw) according to gnutls docs, but do not.
            // REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(client_seed, server_pubkey)); // mismatch
            // REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(client_pubkey, client_seed)); // wrong order
        };

        SECTION("Keys Load Correctly")
        {
            REQUIRE_NOTHROW(GNUTLSCreds::make_from_ed_keys(client_seed, client_pubkey));
        };
    };

    TEST_CASE("008 - Ed Keys: Handshakes", "[008][edkeys][execute]")
    {
        bool key_was_allowed{false};

        auto client_seed = oxenc::from_hex("468e7ed2cd914ca44568e7189245c7b8e5488404fc88a4019c73b51d9dbc48a5");
        auto client_pk = oxenc::from_hex("626136fe40c8860ee5bdc57fd9f15a03ef6777bb9237c18fc4d7ef2aacfe4f88");

        auto server_seed = oxenc::from_hex("fefbb50cdd4cde3be0ae75042c44ff42b026def4fd6be4fb1dc6e81ea0480c9b");
        auto server_pk = oxenc::from_hex("d580d5c68937095ea997f6a88f07a86cdd26dfa0d7d268e80ea9bbb5f3ca0304");

        auto always_allow_cb = callback_waiter{[&](const oxen::quic::gnutls_key&, const std::string_view&) {
            key_was_allowed = true;
            return true;
        }};

        auto always_deny_cb = callback_waiter{[&](const oxen::quic::gnutls_key&, const std::string_view&) {
            key_was_allowed = false;
            return false;
        }};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        server_tls->set_key_verify_callback(always_allow_cb);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);

        REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

        REQUIRE(always_allow_cb.wait());
        REQUIRE(key_was_allowed);
        // SECTION("All Connections Allowed")
        // {
        // };

        // SECTION("Connection Not Allowed")
        // {
        //     server_tls->set_key_verify_callback(always_deny_cb);

        //     REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

        //     REQUIRE(always_deny_cb.wait());
        //     REQUIRE_FALSE(key_was_allowed);
        // };

        // SECTION("Connection Allowed By Pubkey")
        // {
        //     server_tls2->set_key_verify_callback(always_allow_cb);
        //     server_tls->set_key_verify_callback(client_key_allowed_cb);

        //     REQUIRE_NOTHROW(client_endpoint->connect(client_remote, server_tls2));

        //     REQUIRE(client_key_allowed_cb.wait());
        //     REQUIRE(key_was_allowed);
        // };

        // SECTION("Connection Not Allowed By Pubkey")
        // {
        //     server_tls->set_key_verify_callback(client_key_allowed_cb);

        //     REQUIRE_NOTHROW(client_endpoint->connect(client_remote, server_tls));

        //     REQUIRE(client_key_allowed_cb.wait());
        //     REQUIRE_FALSE(key_was_allowed);
        // };
    };

}  // namespace oxen::quic::test
