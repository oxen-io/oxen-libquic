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

        auto client_seed = oxenc::from_hex("468e7ed2cd914ca44568e7189245c7b8e5488404fc88a4019c73b51d9dbc48a5");
        auto client_pubkey = oxenc::from_hex("626136fe40c8860ee5bdc57fd9f15a03ef6777bb9237c18fc4d7ef2aacfe4f88");
        oxen::quic::gnutls_key client_pubkey_array;
        std::copy(client_pubkey.begin(), client_pubkey.end(), client_pubkey_array.data());

        auto server_seed = oxenc::from_hex("fefbb50cdd4cde3be0ae75042c44ff42b026def4fd6be4fb1dc6e81ea0480c9b");
        auto server_pubkey = oxenc::from_hex("d580d5c68937095ea997f6a88f07a86cdd26dfa0d7d268e80ea9bbb5f3ca0304");
        oxen::quic::gnutls_key server_pubkey_array;
        std::copy(server_pubkey.begin(), server_pubkey.end(), server_pubkey_array.data());

        Network test_net{};

        auto client_tls = GNUTLSCreds::make_from_ed_keys(client_seed, client_pubkey);
        auto server_tls = GNUTLSCreds::make_from_ed_keys(server_seed, server_pubkey, /*snode = */ true);
        auto server_tls2 = GNUTLSCreds::make_from_ed_keys(client_seed, client_pubkey, /*snode = */ true);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::local_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);

        std::promise<bool> key_was_allowed;
        bool remote_was_relay{false};
        auto f = key_was_allowed.get_future();

        auto client_key_allowed_cb = [&](const oxen::quic::gnutls_key& key, bool is_relay) {
            remote_was_relay = is_relay;
            if (not is_relay)
            {
                key_was_allowed.set_value(true);
                return true;
            }

            if (key == client_pubkey_array)
            {
                key_was_allowed.set_value(true);
                return true;
            }

            log::error(
                    log_cat,
                    "Key mismatch:\n{}\n{}",
                    oxenc::to_hex(key.begin(), key.end()),
                    oxenc::to_hex(client_pubkey_array.begin(), client_pubkey_array.end()));

            key_was_allowed.set_value(false);
            return false;
        };

        auto always_allow_cb = [&](auto, bool is_relay) {
            remote_was_relay = is_relay;
            key_was_allowed.set_value(true);
            return true;
        };

        auto always_deny_cb = [&](auto, bool is_relay) {
            remote_was_relay = is_relay;
            key_was_allowed.set_value(false);
            return false;
        };

        client_tls->set_key_verify_callback(client_key_allowed_cb);
        server_tls2->set_key_verify_callback(always_allow_cb);

        SECTION("All Connections Allowed")
        {
            server_tls->set_key_verify_callback(always_allow_cb);

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

            require_future(f);
            REQUIRE(not remote_was_relay);
            REQUIRE(f.get() == true);
        };

        SECTION("Connection Not Allowed")
        {
            server_tls->set_key_verify_callback(always_deny_cb);

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, client_tls));

            require_future(f);
            REQUIRE(not remote_was_relay);
            REQUIRE(f.get() == false);
        };

        SECTION("Connection Allowed By Pubkey")
        {
            server_tls->set_key_verify_callback(client_key_allowed_cb);

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, server_tls2));

            require_future(f);
            REQUIRE(remote_was_relay);
            REQUIRE(f.get() == true);
        };

        SECTION("Connection Not Allowed By Pubkey")
        {
            server_tls->set_key_verify_callback(client_key_allowed_cb);

            REQUIRE_NOTHROW(client_endpoint->connect(client_remote, server_tls));

            require_future(f);
            REQUIRE(remote_was_relay);
            REQUIRE(f.get() == false);
        };
    };

}  // namespace oxen::quic::test
