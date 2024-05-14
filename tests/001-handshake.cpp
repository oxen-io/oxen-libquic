#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "tcp.hpp"
#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("001 - Handshaking: Types", "[001][handshake][tls][types]")
    {
        SECTION("TLS Credentials")
        {
            auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();
            REQUIRE_NOTHROW(GNUTLSCreds::make_from_ed_keys(defaults::CLIENT_SEED, defaults::CLIENT_PUBKEY));
            REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(""s, ""s));
        }

        SECTION("Address objects")
        {
            Address empty_addr{};
            Address empty_addr2{"", 0};
            Address good_addr{"127.0.0.1", 4400};
            Address public_addr{"1.2.3.4", 56789};
            Address public_anyport{"4.5.6.7", 0};
            Address localnet_addr{"192.168.1.1", 80};
            Address ipv6_localhost{"::1", 123};
            Address localnet_ipv6{"fdab:1234:5::1", 123};
            Address public_ipv6{"2345::1", 45678};
            Address any_ipv6{"::", 12345};
            Address any_ipv4{"0.0.0.0", 12345};

            CHECK(empty_addr.is_set());
            CHECK_THROWS(Address{"127.001", 4400});
            CHECK_NOTHROW(Address{"", 0});
            CHECK(empty_addr == Address{"::", 0});
            CHECK(good_addr.is_set());

            CHECK(empty_addr.is_any_addr());
#ifndef OXEN_QUIC_ADDRESS_NO_DUAL_STACK
            CHECK(empty_addr.is_ipv6());
            CHECK_FALSE(empty_addr.is_ipv4());
            CHECK(empty_addr.dual_stack);
#else
            CHECK_FALSE(empty_addr.is_ipv6());
            CHECK(empty_addr.is_ipv4());
            CHECK_FALSE(empty_addr.dual_stack);
#endif
            CHECK(empty_addr.is_any_port());
            CHECK_FALSE(empty_addr.is_addressable());
            CHECK_FALSE(empty_addr.is_loopback());
            CHECK_FALSE(any_ipv6.dual_stack);
            CHECK_FALSE(any_ipv4.dual_stack);

            CHECK(empty_addr == empty_addr2);

            CHECK_FALSE(good_addr.is_public());
            CHECK_FALSE(good_addr.is_public_ip());
            CHECK_FALSE(good_addr.is_any_addr());
            CHECK_FALSE(good_addr.is_any_port());
            CHECK(good_addr.is_addressable());
            CHECK(good_addr.is_loopback());

            CHECK(public_addr.is_public());
            CHECK(public_addr.is_public_ip());
            CHECK_FALSE(public_addr.is_any_addr());
            CHECK_FALSE(public_addr.is_any_port());
            CHECK(public_addr.is_addressable());
            CHECK_FALSE(public_addr.is_loopback());

            CHECK_FALSE(public_anyport.is_public());
            CHECK(public_anyport.is_public_ip());
            CHECK_FALSE(public_anyport.is_any_addr());
            CHECK(public_anyport.is_any_port());
            CHECK_FALSE(public_anyport.is_addressable());
            CHECK_FALSE(public_anyport.is_loopback());

            CHECK_FALSE(localnet_addr.is_public());
            CHECK_FALSE(localnet_addr.is_public_ip());
            CHECK_FALSE(localnet_addr.is_any_addr());
            CHECK_FALSE(localnet_addr.is_any_port());
            CHECK(localnet_addr.is_addressable());
            CHECK_FALSE(localnet_addr.is_loopback());

            CHECK_FALSE(ipv6_localhost.is_public());
            CHECK_FALSE(ipv6_localhost.is_public_ip());
            CHECK_FALSE(ipv6_localhost.is_any_addr());
            CHECK_FALSE(ipv6_localhost.is_any_port());
            CHECK(ipv6_localhost.is_addressable());
            CHECK(ipv6_localhost.is_loopback());

            CHECK_FALSE(localnet_ipv6.is_public());
            CHECK_FALSE(localnet_ipv6.is_public_ip());
            CHECK_FALSE(localnet_ipv6.is_any_addr());
            CHECK_FALSE(localnet_ipv6.is_any_port());
            CHECK(localnet_ipv6.is_addressable());
            CHECK_FALSE(localnet_ipv6.is_loopback());

            CHECK(public_ipv6.is_public());
            CHECK(public_ipv6.is_public_ip());
            CHECK_FALSE(public_ipv6.is_any_addr());
            CHECK_FALSE(public_ipv6.is_any_port());
            CHECK(public_ipv6.is_addressable());
            CHECK_FALSE(public_ipv6.is_loopback());

            CHECK(Address{"127.0.0.1", 2} < Address{"127.0.0.1", 256});
            CHECK(Address{"127.0.0.1", 256} < Address{"127.0.0.2", 2});
            CHECK(Address{"127.0.0.1", 256} < public_ipv6);
            CHECK(Address{"127.0.0.1", 2} == Address{"127.0.0.1", 2});
            CHECK(Address{"127.0.0.1", 256} > Address{"127.0.0.1", 2});
            CHECK(Address{"127.0.0.1", 256} <= public_ipv6);
            CHECK(public_ipv6 >= Address{"127.0.0.1", 256});
        }

        SECTION("Object serialization", "[serialization]")
        {
            Address addr{"127.0.0.1", 4400};
            auto addr_str = addr.bt_encode();
            oxenc::bt_dict_consumer addr_btdc{addr_str};
            Address maybe_addr;

            REQUIRE_NOTHROW(maybe_addr = *Address::bt_decode(addr_btdc));
            REQUIRE(addr == maybe_addr);

            Address local{"127.0.0.1", 5566}, remote{"127.0.0.1", 3257};

            Path p{local, remote};
            auto path_str = p.bt_encode();
            oxenc::bt_dict_consumer path_btdc{path_str};
            Path maybe_path;

            REQUIRE_NOTHROW(maybe_path = *Path::bt_decode(path_btdc));
            REQUIRE(p == maybe_path);

            bstring payload = "goodmorning"_bs;
            Packet pkt{p, payload};
            auto pkt_str = pkt.bt_encode();
            std::optional<Packet> maybe_pkt;

            REQUIRE_NOTHROW(
                    maybe_pkt =
                            *Packet::bt_decode(bstring{reinterpret_cast<const std::byte*>(pkt_str.data()), pkt_str.size()}));

            REQUIRE(*maybe_pkt == pkt);
            REQUIRE(pkt_str == maybe_pkt->bt_encode());
        }

        SECTION("IP Address Ranges", "[range][operators][ipaddr]")
        {
            CHECK((ipv4(10, 0, 0, 0) / 8).contains(ipv4(10, 0, 0, 0)));
            CHECK((ipv4(10, 0, 0, 0) / 8).contains(ipv4(10, 255, 255, 255)));
            CHECK((ipv4(10, 123, 45, 67) / 8).contains(ipv4(10, 123, 123, 123)));
            CHECK((ipv4(10, 255, 255, 255) / 8).contains(ipv4(10, 0, 0, 0)));
            CHECK((ipv4(10, 255, 255, 255) / 8).contains(ipv4(10, 123, 123, 123)));
            CHECK_FALSE((ipv4(10, 0, 0, 0) / 8).contains(ipv4(11, 0, 0, 0)));
            CHECK_FALSE((ipv4(10, 0, 0, 0) / 8).contains(ipv4(9, 255, 255, 255)));

            CHECK((ipv6(0x2001, 0xdb8) / 32).contains(ipv6(0x2001, 0xdb8)));
            CHECK((ipv6(0x2001, 0xdb8) / 32).contains(ipv6(0x2001, 0xdb8, 0xffff, 0xffff)));
            CHECK((ipv6(0x2001, 0xdb8, 0xffff) / 32).contains(ipv6(0x2001, 0xdb8)));
            CHECK((ipv6(0x2001, 0xdb8, 0xffff) / 32).contains(ipv6(0x2001, 0xdb8)));
        }

        SECTION("IPv4 Addresses", "[ipv4][constructors][ipaddr]")
        {
            uint32_t v4_n;                      // network order ipv4 addr
            auto v4_h = "192.168.1.1"s;         // host order ipv4 string
            auto v4_full = "192.168.1.1:123"s;  // full ipv4 addr/port string

            REQUIRE(inet_pton(AF_INET, v4_h.c_str(), &v4_n));

            in_addr v4_inaddr;
#ifndef _WIN32
            v4_inaddr.s_addr = v4_n;
#else
            v4_inaddr.S_un.S_addr = v4_n;
#endif

            ipv4 v4_net_order{v4_n};
            ipv4 v4_private{v4_h};

            Address v4_from_ipv4{v4_private, 123};
            Address v4_from_ipv4_n{v4_net_order, 123};
            Address v4_from_inaddr{};
            v4_from_inaddr.set_addr(&v4_inaddr);
            v4_from_inaddr.set_port(123);

            CHECK(v4_from_ipv4 == v4_from_ipv4_n);
            CHECK(v4_from_ipv4_n == v4_from_inaddr);

            CHECK(v4_net_order == v4_inaddr);
            CHECK(v4_private == v4_net_order);

            CHECK(v4_private.to_string() == v4_h);
            CHECK(v4_net_order.to_string() == v4_h);

            auto ipv4_from_addr = v4_from_ipv4.to_ipv4();
            auto ipv4_from_addr_n = v4_from_ipv4_n.to_ipv4();

            REQUIRE(ipv4_from_addr == ipv4_from_addr_n);

            CHECK(ipv4_from_addr == v4_private);
            CHECK(ipv4_from_addr == v4_net_order);

            CHECK(v4_from_ipv4.to_string() == v4_full);
            CHECK(v4_from_ipv4_n.to_string() == v4_full);
        }

        SECTION("IPv6 Addresses", "[ipv6][constructors][ipaddr]")
        {
            auto weird = "::ffff:192.0.2.1"s;
            Address localnet_ipv6{"fdab:1234:5::1", 123};

            in6_addr localnet_in6addr = localnet_ipv6.in6().sin6_addr;

            ipv6 addr_localnet{0xfdab, 0x1234, 0x0005, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001};
            ipv6 addr_from_in6addr{&localnet_in6addr};
            in6_addr localnet_from_ipv6 = addr_from_in6addr.to_in6();

            ipv6 weird_addr{weird};

            Address address_from_v6{addr_localnet, 123};
            Address address_from_v6_in6{addr_from_in6addr, 123};

            CHECK(addr_localnet == addr_from_in6addr);
            CHECK(!std::memcmp(localnet_from_ipv6.s6_addr, localnet_in6addr.s6_addr, sizeof(in6_addr)));
            CHECK(addr_localnet.to_string() == addr_from_in6addr.to_string());

            CHECK(localnet_ipv6.to_string() == address_from_v6.to_string());
            CHECK(address_from_v6.to_string() == address_from_v6_in6.to_string());

            CHECK(weird_addr.to_string() == weird);

            Address weird_v4{weird, 80};
            Address localnet_v4{"192.0.2.1", 80};

            localnet_v4.map_ipv4_as_ipv6();
            REQUIRE(localnet_v4.is_ipv4_mapped_ipv6());

            CHECK(weird_v4.to_string() == localnet_v4.to_string());
        }

        SECTION("Endpoint object creation - Default addressing")
        {
            Network test_net{};
            Address default_addr{};

            auto ep = test_net.endpoint(default_addr);
            // Note: kernel chooses a random port after being passed default addr
            CHECK_FALSE(ep->local().to_string() == default_addr.to_string());
        }
    }

    TEST_CASE("001 - Handshaking: Incorrect pubkeys", "[001][client][incorrect][pubkeys]")
    {
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        SECTION("Incorrect pubkey in remote")
        {
            uint64_t client_error{0}, client_attempt{0};

            auto client_established_2 = callback_waiter{[&client_attempt](connection_interface&) { client_attempt = 1000; }};

            auto client_closed = callback_waiter{[&client_error](connection_interface&, uint64_t) { client_error = 1000; }};

            auto client_endpoint = test_net.endpoint(client_local, client_established_2, client_closed);

            RemoteAddress bad_client_remote{defaults::CLIENT_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_ci = client_endpoint->connect(bad_client_remote, client_tls);

            CHECK(not client_established_2.wait(500ms));
            CHECK(client_attempt != 1000);
            CHECK(client_closed.wait(10s));
            CHECK(client_error == 1000);
        }

        SECTION("Incorrect pubkey length")
        {
            auto client_endpoint = test_net.endpoint(client_local);

            auto short_key = defaults::SERVER_PUBKEY.substr(0, 31);

            RemoteAddress bad_client_remote{short_key, "127.0.0.1"s, server_endpoint->local().port()};

            REQUIRE_THROWS(client_endpoint->connect(bad_client_remote, client_tls));
        }

        SECTION("No pubkey in remote")
        {
            // If uncommented, this line will not compile! Remote addresses must pass a remote pubkey to be
            // verified upon the client successfully establishing connection with a remote.

            // RemoteAddress client_remote{"127.0.0.1"s, server_endpoint->local().port()};
            CHECK(true);
        }

        SECTION("No TLS creds in connect/listen")
        {
            // If uncommented, any of these lines should not compile! connect() and listen()
            // each require exactly one TLSCreds shared pointer to be provided.

            // server_endpoint->connect(client_remote);                          // no tls
            // server_endpoint->connect(client_tls, client_remote, client_tls);  // multiple tls
            // server_endpoint->listen(client_remote);                           // no tls
            // server_endpoint->listen(server_tls, client_remote, server_tls);   // multiple tls

            CHECK(true);
        }
    }

    TEST_CASE("001 - Handshaking: Pubkey successes", "[001][client][correct][pubkeys]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);

        SECTION("Correct pubkey in remote")
        {
            auto client_ci = client_endpoint->connect(client_remote, client_tls);

            // This will return false until the connection has had time to establish and validate. Depending
            // on the architecture running the test, the connection may be already established and validated
            // by the time this line es executed
            CHECK_NOFAIL(client_ci->is_validated());

            CHECK(client_established.wait());
            CHECK(server_established.wait());
            CHECK(client_ci->is_validated());
        }

        SECTION("Immediate network shutdown after calling connect")
        {
            test_net.set_shutdown_immediate();

            CHECK_NOTHROW(client_endpoint->connect(client_remote, client_tls));
        }
    }

    TEST_CASE("001 - Handshaking: Server Validation", "[001][server]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        server_tls->set_key_verify_callback([](const ustring_view& key, const ustring_view&) {
            return key == convert_sv<unsigned char>(std::string_view{defaults::CLIENT_PUBKEY});
        });

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto server_cis = server_endpoint->get_all_conns(Direction::INBOUND);
        REQUIRE(!server_cis.empty());
        auto& server_ci = server_cis.front();
        CHECK(client_ci->is_validated());
        CHECK(server_ci->is_validated());
        CHECK(server_ci->remote_key() == ustring{reinterpret_cast<const unsigned char*>(defaults::CLIENT_PUBKEY.data()),
                                                 defaults::CLIENT_PUBKEY.length()});
    }

    TEST_CASE("001 - Handshaking: Types - IPv6", "[001][ipv6]")
    {
        if (disable_ipv6)
            SKIP("IPv6 not enabled for this test iteration!");

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "::1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);

        CHECK_NOTHROW(client_endpoint->connect(client_remote, client_tls));
        CHECK(client_established.wait());
        CHECK(server_established.wait());
    }

    TEST_CASE("001 - Handshaking: Execution", "[001][handshake][tls][execute]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());
        CHECK(client_ci->is_validated());
    }

    TEST_CASE("001 - multi-listen failure", "[001][dumb][listen][protection]")
    {
        Network net;
        auto ep = net.endpoint(Address{});

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        CHECK_NOTHROW(ep->listen(server_tls));
        CHECK_THROWS_AS(ep->listen(server_tls), std::logic_error);
    }

    TEST_CASE("001 - Path local address", "[001][handshake][path][local]")
    {
        Path client_path, server_path;
        auto client_established = callback_waiter{[&](connection_interface& ci) { client_path = ci.path(); }};
        auto server_established = callback_waiter{[&](connection_interface& ci) { server_path = ci.path(); }};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{"0.0.0.0", 0};
        Address client_local{"0.0.0.0", 0};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        // Client should see it's any address as local:
        CHECK(client_path.local.host() == "0.0.0.0");
        // But server should see the address the client connected to, even though it's listening on
        // the any address:
        CHECK(server_path.local.host() == "127.0.0.1");
    }

    TEST_CASE("001 - Non-default path local address", "[001][handshake][path][local][nondefault]")
    {
        // This test is very similar to the above, but uses a connection to 127.0.0.2 instead of
        // 127.0.0.1 (which generally doesn't work on macOS, even though the entire 127.0.0.1/8
        // range is supposed to be localhost).
        //
        // Unlike the above, here the client connects to 127.0.0.2 and so, if the server sends back
        // packets without properly setting the source address, those packets will come from
        // 127.0.0.1, not .2, and the client will drop them as coming from an unknown path and thus
        // the connection to the server will fail.

#if defined(__APPLE__)
        SKIP("This test requires 127.0.0.2, which doesn't work on Apple");
#endif
        if (EMULATING_HELL)
            SKIP("This test requires 127.0.0.2, which doesn't work under WINE");

        Path client_path, server_path;
        auto client_established = callback_waiter{[&](connection_interface& ci) { client_path = ci.path(); }};
        auto server_established = callback_waiter{[&](connection_interface& ci) { server_path = ci.path(); }};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{"0.0.0.0", 0};
        Address client_local{"0.0.0.0", 0};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.2"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        CHECK(client_path.local.host() == "0.0.0.0");
        CHECK(server_path.local.host() == "127.0.0.2");
    }

    TEST_CASE("001 - Handshaking: simultaneous bidirection connection resolution", "[001][defer][quietclose]")
    {
        // This test is designed to test a scenario where A and B connect to each other
        // simultaneously and want to coordinate on which of the two connections to keep alive by
        // using `set_close_quietly` on the one to be dropped.

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        // Instead of using randomly generated seeds and pubkeys, hardcoded strings are used to deterministically
        // produce the same test result. The key verify callback compares the pubkeys in lexicographical order,
        // deferring to the connetion initiated by the pubkey that appears first in said order.
        constexpr auto C_SEED = "468e7ed2cd914ca44568e7189245c7b8e5488404fc88a4019c73b51d9dbc48a5"_hex;
        constexpr auto C_PUBKEY = "626136fe40c8860ee5bdc57fd9f15a03ef6777bb9237c18fc4d7ef2aacfe4f88"_hex;
        constexpr auto S_SEED = "fefbb50cdd4cde3be0ae75042c44ff42b026def4fd6be4fb1dc6e81ea0480c9b"_hex;
        constexpr auto S_PUBKEY = "d580d5c68937095ea997f6a88f07a86cdd26dfa0d7d268e80ea9bbb5f3ca0304"_hex;

        Network test_net{};

        std::shared_ptr<connection_interface> server_ci, client_ci;
        std::mutex ci_mutex;

        auto client_tls = GNUTLSCreds::make_from_ed_keys(C_SEED, C_PUBKEY);
        auto server_tls = GNUTLSCreds::make_from_ed_keys(S_SEED, S_PUBKEY);

        std::vector<std::array<std::string, 3>> defer_i_l_r;  // incoming/local/remote

        auto defer_hook = [&defer_i_l_r](
                                  std::string_view incoming,
                                  std::string_view local,
                                  std::string_view remote,
                                  std::shared_ptr<connection_interface> local_outbound) -> bool {
            defer_i_l_r.push_back({std::string{incoming}, std::string{local}, std::string{remote}});

            // If the LHS parameter to std::strcmp appears FIRST in lexicographical order, then rv < 0. As a result,
            // if the incoming pubkey appears BEFORE the server pubkey in lexicographical order, we will defer to the
            // connection initiated by the remote -- ergo we will ACCEPT this connection and mark the local endpoint's
            // connection as "die silently" (close w/o executing any callbacks or writing any close packets). Else, we
            // will REJECT the incoming connection and defer to the local endpoint's outgoing connection
            auto defer_to_incoming = incoming < local;

            if (defer_to_incoming)
                local_outbound->set_close_quietly();

            return defer_to_incoming;
        };

        server_tls->set_key_verify_callback([&](const ustring_view& key, const ustring_view&) {
            std::lock_guard lock{ci_mutex};
            return defer_hook({reinterpret_cast<const char*>(key.data()), key.size()}, S_PUBKEY, C_PUBKEY, server_ci);
        });

        client_tls->set_key_verify_callback([&](const ustring_view& key, const ustring_view&) {
            std::lock_guard lock{ci_mutex};
            return defer_hook(
                    std::string{reinterpret_cast<const char*>(key.data()), key.size()}, C_PUBKEY, S_PUBKEY, client_ci);
        });

        Address server_local{};
        Address client_local{};

        SECTION("Override endpoint level callback", "[override][closehook][endpoint]")
        {
            auto p = std::promise<bool>();
            auto f = p.get_future();

            auto server_closed_ep_level = [&](connection_interface& ci, uint64_t) {
                // The endpoint-level callback will be called for the connection that was initiated by the
                // client, as the client's pubkey dictates it's connection is to be deferred to. As a result,
                // the reference ID will be different than that of the connection initiated by the server.
                p.set_value(ci.reference_id() != server_ci->reference_id());
            };

            auto server_endpoint = test_net.endpoint(server_local, server_established, server_closed_ep_level);

            RemoteAddress client_remote{S_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);

            RemoteAddress server_remote{C_PUBKEY, "127.0.0.1"s, client_endpoint->local().port()};

            server_endpoint->listen(server_tls);
            client_endpoint->listen(client_tls);

            {
                std::lock_guard lock{ci_mutex};
                client_ci = client_endpoint->connect(client_remote, client_tls);
                server_ci = server_endpoint->connect(server_remote, server_tls);
            }

            CHECK(client_established.wait());

            // By signalling to close all connections, we will ensure that the above promise is set during
            // closure of the connection that was preferred.
            client_endpoint->close_conns();

            require_future(f, 5s);
            CHECK(f.get());  // Deferred check for ci.reference_id() != server_ci->reference_id()
        }

        SECTION("Override connection level callback", "[override][closehook][connection]")
        {
            auto server_closed_conn_level = callback_waiter{[](connection_interface&, uint64_t) {
                throw std::runtime_error{"ERROR: THIS CONNECTION SHOULD BE QUIET CLOSING"};
            }};

            auto server_endpoint = test_net.endpoint(server_local, server_established);

            RemoteAddress client_remote{S_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established);

            RemoteAddress server_remote{C_PUBKEY, "127.0.0.1"s, client_endpoint->local().port()};

            server_endpoint->listen(server_tls);
            client_endpoint->listen(client_tls);

            {
                std::lock_guard lock{ci_mutex};
                client_ci = client_endpoint->connect(client_remote, client_tls);
                server_ci = server_endpoint->connect(server_remote, server_tls, server_closed_conn_level);
            }

            CHECK(client_established.wait());
            client_endpoint->close_conns();

            CHECK_FALSE(server_closed_conn_level.is_ready());
        }

        // This test is inherently racy (by design), but leads to rare data race conditions during
        // destruction; this hacky sleep is here to try to resolve it by adding just a tiny extra
        // window for things to settle down before we start destroying things.
        std::this_thread::sleep_for(50ms);

        for (const auto& [incoming, local, remote] : defer_i_l_r)
        {
            CHECK(oxenc::to_hex(incoming) == oxenc::to_hex(remote));
            // The pubkeys definitely should not be the same
            CHECK(oxenc::to_hex(incoming) != oxenc::to_hex(local));
        }
    }

    TEST_CASE("001 - Idle timeout", "[001][idle][timeout]")
    {
        Network net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        uint64_t server_errcode = 4242;
        uint64_t client_errcode = 424242;

        callback_waiter server_conn_closed{
                [&server_errcode](connection_interface&, uint64_t errcode) { server_errcode = errcode; }};
        callback_waiter client_conn_closed{
                [&client_errcode](connection_interface&, uint64_t errcode) { client_errcode = errcode; }};

        auto server_endpoint = net.endpoint(server_local, server_conn_closed);
        auto client_endpoint = net.endpoint(client_local, client_conn_closed);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        SECTION("Client fast timeout")
        {
            server_endpoint->listen(server_tls);
            auto client_ci = client_endpoint->connect(client_remote, client_tls, opt::idle_timeout{250ms});
        }
        SECTION("Server fast timeout")
        {
            server_endpoint->listen(server_tls, opt::idle_timeout{250ms});
            auto client_ci = client_endpoint->connect(client_remote, client_tls);
        }

        CHECK_FALSE(server_conn_closed.wait(100ms));

        CHECK(server_conn_closed.wait(500ms));
        CHECK(server_errcode == CONN_IDLE_CLOSED);
        CHECK(client_conn_closed.wait(500ms));
        CHECK(client_errcode == CONN_IDLE_CLOSED);
    }

    TEST_CASE("001 - Handshake timeout", "[001][handshake][timeout]")
    {
        auto net1 = std::make_unique<Network>();
        Network net2{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        uint64_t client_errcode = 424242;

        callback_waiter client_conn_closed{
                [&client_errcode](connection_interface&, uint64_t errcode) { client_errcode = errcode; }};

#if 0
        // This code doesn't work: ngtcp2 (at least as of 1.1.0) apparently considers the client to
        // be post-handshake by the point the server gets this key (presumably because it doesn't
        // need anything else from the server), so the handshake established timeout just doesn't
        // fire on the client and, no matter how long we block the server, the only timeout that
        // will happen is the idle timeout.
        server_tls->set_key_verify_callback([](const ustring_view&, const ustring_view&) {
            // This stalls the entire network object; this is a really terrible thing to do outside
            // of test code, but will let us simulate a slow handshake.
            log::critical(log_cat, "key verify sleeping...");
            std::this_thread::sleep_for(30s);
            log::critical(log_cat, "key verify done sleeping");
            return true;
        });
#endif
        // So what we do instead is just shutdown the server's network entirely before even trying
        // to connect to client.  Unfortunately we don't really have a way to reliably kill the
        // outgoing client connection mid-handshake, so these tests can only really *half* test that
        // the handshake argument is being dealt with properly (not ideal, but probably fine since
        // the Connection code is largely the same in terms of where it deals with the handshake
        // timeout value).

        std::shared_ptr<Endpoint> client_endpoint;
        std::shared_ptr<connection_interface> client_ci;

        auto server_endpoint = net1->endpoint(server_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        server_endpoint.reset();
        net1.reset();  // kill the server

#ifdef __APPLE__
        constexpr int macos_sucks = 10;
#else
        constexpr int macos_sucks = 1;
#endif

        opt::handshake_timeout timeout{100ms * macos_sucks};

        SECTION("Client endpoint handshake timeout")
        {
            client_endpoint = net2.endpoint(client_local, client_conn_closed, timeout);
            client_ci = client_endpoint->connect(client_remote, client_tls);
        }
        SECTION("Client connect handshake timeout")
        {
            client_endpoint = net2.endpoint(client_local, client_conn_closed);
            client_ci = client_endpoint->connect(client_remote, client_tls, timeout);
        }
        CHECK_FALSE(client_conn_closed.wait(25ms * macos_sucks));

        CHECK(client_conn_closed.wait(125ms * macos_sucks));
        CHECK(client_errcode == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT));
    }

    TEST_CASE("001 - Handshake timeout stream close", "[001][handshake][timeout][stream]")
    {
        auto net1 = std::make_unique<Network>();
        Network net2{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        uint64_t client_errcode = 424242;

        callback_waiter client_conn_closed{
                [&client_errcode](connection_interface&, uint64_t errcode) { client_errcode = errcode; }};

        std::optional<bool> stream_callback_called;
        std::shared_ptr<Endpoint> client_endpoint;
        std::shared_ptr<connection_interface> client_ci;

        auto server_endpoint = net1->endpoint(server_local);
        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        server_endpoint.reset();
        net1.reset();  // kill the server

#ifdef __APPLE__
        constexpr int macos_sucks = 10;
#else
        constexpr int macos_sucks = 1;
#endif

        opt::handshake_timeout timeout{100ms * macos_sucks};

        SECTION("Client endpoint handshake timeout")
        {
            client_endpoint = net2.endpoint(client_local, client_conn_closed, timeout);
            client_ci = client_endpoint->connect(client_remote, client_tls);
            auto client_bp = client_ci->open_stream<BTRequestStream>();
            client_bp->command("hi", "body", [&](message m) { stream_callback_called = m.timed_out; });
        }
        CHECK_FALSE(client_conn_closed.wait(25ms * macos_sucks));

        CHECK(client_conn_closed.wait(125ms * macos_sucks));
        REQUIRE(stream_callback_called);
        CHECK(*stream_callback_called);
    }
}  // namespace oxen::quic::test
