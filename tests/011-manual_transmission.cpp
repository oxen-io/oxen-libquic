#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    TEST_CASE("011 - Manual Transmission: Both ends re-route", "[011][manual][bidi]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;

        Address server_local{};
        Address client_local{};

        opt::manual_routing client_sender{[&](const Path& p, bstring_view d) {
            server_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        opt::manual_routing server_sender{[&](const Path& p, bstring_view d) {
            client_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        server_endpoint = test_net.endpoint(server_local, server_sender, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, server_local};

        client_endpoint = test_net.endpoint(client_local, client_sender, client_established);

        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        require_future(d_future);
    }

    /** Binary test case:
        This is designed to emulate the use case in which a manually routed endpoint is using a normal QUIC endpoint as a
        tunnel to connect to a remote manual endpoint.

        [manual client] <- manual -> [vanilla client] <- quic datagram -> [vanilla server] <- manual -> [manual server]
    */
    TEST_CASE("011 - Manual Transmission: Binary endpoints tunneled over datagrams", "[011][manual][binary][datagrams]")
    {
        auto vanilla_client_established = callback_waiter{[](connection_interface&) {}};
        auto manual_client_established = callback_waiter{[](connection_interface&) {}};
        auto vanilla_server_established = callback_waiter{[](connection_interface&) {}};
        auto manual_server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        std::shared_ptr<connection_interface> vanilla_client_ci, vanilla_server_ci, manual_client_ci;

        std::shared_ptr<Endpoint> manual_client, vanilla_client, manual_server, vanilla_server;

        Address manual_server_addr{}, vanilla_server_addr{};
        Address manual_client_addr{}, vanilla_client_addr{};

        opt::enable_datagrams enable_dgrams{Splitting::ACTIVE};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        // The receiving (remote) end of the tunnel composes the packet
        SECTION("Receiv-side packet reconstruction")
        {
            dgram_data_callback vanilla_client_recv_dgram_cb = [&](dgram_interface&, bstring data) {
                manual_client->manually_receive_packet(Packet{Path{}, std::move(data)});
            };

            dgram_data_callback vanilla_server_recv_dgram_cb = [&](dgram_interface&, bstring data) {
                manual_server->manually_receive_packet(Packet{Path{}, std::move(data)});
            };

            opt::manual_routing manual_client_sender{
                    [&](const Path&, bstring_view d) { vanilla_client_ci->send_datagram(bstring{d}); }};

            opt::manual_routing manual_server_sender{
                    [&](const Path&, bstring_view d) { vanilla_server_ci->send_datagram(bstring{d}); }};

            vanilla_server = test_net.endpoint(
                    vanilla_server_addr, vanilla_server_established, enable_dgrams, vanilla_server_recv_dgram_cb);
            vanilla_client = test_net.endpoint(
                    vanilla_client_addr, vanilla_client_established, enable_dgrams, vanilla_client_recv_dgram_cb);
            manual_client = test_net.endpoint(manual_client_addr, manual_client_sender, manual_client_established);
            manual_server = test_net.endpoint(manual_server_addr, manual_server_sender, manual_server_established);
        }

        // The sender (local) of the packet bt-encodes the packet prior to tranmission
        SECTION("Send-side packet construction")
        {
            dgram_data_callback vanilla_client_recv_dgram_cb = [&](dgram_interface&, bstring data) {
                manual_client->manually_receive_packet(*Packet::bt_decode(std::move(data)));
            };

            dgram_data_callback vanilla_server_recv_dgram_cb = [&](dgram_interface&, bstring data) {
                manual_server->manually_receive_packet(*Packet::bt_decode(std::move(data)));
            };

            opt::manual_routing manual_client_sender{[&](const Path& p, bstring_view d) {
                vanilla_client_ci->send_datagram(Packet{p, bstring{d}}.bt_encode());
            }};

            opt::manual_routing manual_server_sender{[&](const Path& p, bstring_view d) {
                vanilla_server_ci->send_datagram(Packet{p, bstring{d}}.bt_encode());
            }};

            vanilla_server = test_net.endpoint(
                    vanilla_server_addr, vanilla_server_established, enable_dgrams, vanilla_server_recv_dgram_cb);
            vanilla_client = test_net.endpoint(
                    vanilla_client_addr, vanilla_client_established, enable_dgrams, vanilla_client_recv_dgram_cb);
            manual_client = test_net.endpoint(manual_client_addr, manual_client_sender, manual_client_established);
            manual_server = test_net.endpoint(manual_server_addr, manual_server_sender, manual_server_established);
        }

        REQUIRE_NOTHROW(vanilla_server->listen(server_tls));
        REQUIRE_NOTHROW(manual_server->listen(server_tls));

        RemoteAddress vanilla_client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, vanilla_server->local().port()};

        vanilla_client_ci = vanilla_client->connect(vanilla_client_remote, client_tls);

        CHECK(vanilla_client_established.wait());
        CHECK(vanilla_server_established.wait());

        std::this_thread::sleep_for(25ms);

        vanilla_server_ci = vanilla_server->get_all_conns(Direction::INBOUND).front();

        CHECK(vanilla_server_ci);

        std::this_thread::sleep_for(25ms);

        RemoteAddress manual_client_remote{defaults::SERVER_PUBKEY};

        manual_client_ci = manual_client->connect(manual_client_remote, client_tls);

        CHECK(manual_client_established.wait());
        CHECK(manual_server_established.wait());
    }

    TEST_CASE("011 - Manual Transmission: Binary endpoints tunneled over streams", "[011][manual][binary][streams]")
    {
        Network test_net{};
        test_net.set_shutdown_immediate();

        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        std::shared_ptr<Endpoint> manual_client, manual_server;

        Address vanilla_server_addr{}, manual_server_addr{}, manual_client_addr{}, vanilla_client_addr{};

        Address manual_server_addr1{"", 1111}, manual_server_addr2{"", 2222}, manual_server_addr3{"", 3333};

        Path path0{manual_client_addr, manual_server_addr}, path1{manual_client_addr, manual_server_addr1},
                path2{manual_client_addr, manual_server_addr2}, path3{manual_client_addr, manual_server_addr3};

        // Paths stored client -> server
        std::unordered_map<int64_t, Path> streamid_to_paths;
        std::unordered_map<Path, int64_t> paths_to_streamid;

        stream_data_callback vanilla_client_stream_data_cb = [&](Stream& s, bstring_view data) {
            if (auto it = streamid_to_paths.find(s.stream_id()); it != streamid_to_paths.end())
                manual_client->manually_receive_packet(Packet{it->second, bstring{data}});
        };

        stream_data_callback vanilla_server_stream_data_cb = [&](Stream& s, bstring_view data) {
            if (auto it = streamid_to_paths.find(s.stream_id()); it != streamid_to_paths.end())
                manual_server->manually_receive_packet(Packet{it->second, bstring{data}});
        };

        stream_data_callback manual_server_stream_data_cb = [&](Stream&, bstring_view data) {
            REQUIRE(good_msg == data);
            d_promise.set_value(true);
        };

        auto vanilla_client_established = callback_waiter{[&](connection_interface&) {}};
        auto vanilla_server_established = callback_waiter{[&](connection_interface&) {}};

        std::shared_ptr<connection_interface> vanilla_client_ci, vanilla_server_ci;

        opt::manual_routing manual_client_sender{[&](const Path& p, bstring_view d) {
            if (auto it = paths_to_streamid.find(p); it != paths_to_streamid.end())
                vanilla_client_ci->get_stream(it->second)->send(bstring{d});
        }};

        opt::manual_routing manual_server_sender{[&](const Path& p, bstring_view d) {
            if (auto it = paths_to_streamid.find(p); it != paths_to_streamid.end())
                vanilla_server_ci->get_stream(it->second)->send(bstring{d});
        }};

        auto manual_client_established0 = callback_waiter{[](connection_interface&) {}};
        auto manual_client_established1 = callback_waiter{[](connection_interface&) {}};
        auto manual_client_established2 = callback_waiter{[](connection_interface&) {}};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto vanilla_server = test_net.endpoint(vanilla_server_addr);
        auto vanilla_client = test_net.endpoint(vanilla_client_addr);

        manual_client = test_net.endpoint(manual_client_addr, manual_client_sender);
        manual_server = test_net.endpoint(manual_server_addr, manual_server_sender);

        REQUIRE_NOTHROW(vanilla_server->listen(server_tls, vanilla_server_established, vanilla_server_stream_data_cb));
        REQUIRE_NOTHROW(manual_server->listen(server_tls, manual_server_stream_data_cb));

        RemoteAddress vanilla_client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, vanilla_server->local().port()};

        vanilla_client_ci = vanilla_client->connect(
                vanilla_client_remote, client_tls, vanilla_client_established, vanilla_client_stream_data_cb);

        CHECK(vanilla_client_established.wait());
        CHECK(vanilla_server_established.wait());

        std::this_thread::sleep_for(25ms);

        REQUIRE(manual_server->is_accepting());

        vanilla_server_ci = vanilla_server->get_all_conns(Direction::INBOUND).front();

        RemoteAddress manual_client_remote0{defaults::SERVER_PUBKEY, path0.remote};

        auto vanilla_client_stream0 = vanilla_client_ci->open_stream();
        streamid_to_paths.emplace(vanilla_client_stream0->stream_id(), path0);
        paths_to_streamid.emplace(path0, vanilla_client_stream0->stream_id());

        auto manual_ci0 = manual_client->connect(manual_client_remote0, client_tls, manual_client_established0);

        CHECK(manual_client_established0.wait());

        std::this_thread::sleep_for(25ms);

        RemoteAddress manual_client_remote1{defaults::SERVER_PUBKEY, path1.remote};

        auto vanilla_client_stream1 = vanilla_client_ci->open_stream();
        streamid_to_paths.emplace(vanilla_client_stream1->stream_id(), path1);
        paths_to_streamid.emplace(path1, vanilla_client_stream1->stream_id());

        auto manual_ci1 = manual_client->connect(manual_client_remote1, client_tls, manual_client_established1);

        CHECK(manual_client_established1.wait());

        std::this_thread::sleep_for(25ms);

        RemoteAddress manual_client_remote2{defaults::SERVER_PUBKEY, path2.remote};

        auto vanilla_client_stream2 = vanilla_client_ci->open_stream();
        streamid_to_paths.emplace(vanilla_client_stream2->stream_id(), path2);
        paths_to_streamid.emplace(path2, vanilla_client_stream2->stream_id());

        auto manual_ci2 = manual_client->connect(manual_client_remote2, client_tls, manual_client_established2);

        CHECK(manual_client_established2.wait());

        std::this_thread::sleep_for(25ms);

        auto manual_stream = manual_ci2->open_stream();
        manual_stream->send(good_msg);
        std::this_thread::sleep_for(25ms);
        require_future(d_future);
    }
}  //  namespace oxen::quic::test
