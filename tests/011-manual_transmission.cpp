#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("011 - Manual Transmission: Both ends re-route", "[011][manual][bidi]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"_bsp;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bspan dat) {
            REQUIRE_THAT(dat, EqualsSpan(good_msg));
            d_promise.set_value(true);
        };

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;

        Address server_local{};
        Address client_local{};

        opt::manual_routing client_sender{
                [&](const Path& p, bspan d) { server_endpoint->manually_receive_packet(Packet{p.invert(), d}); }};

        opt::manual_routing server_sender{
                [&](const Path& p, bspan d) { client_endpoint->manually_receive_packet(Packet{p.invert(), d}); }};

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

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));

        require_future(d_future);
    }

    /** Binary test case:
        This is designed to emulate the use case in which a manually routed endpoint is using a normal QUIC endpoint as a
        tunnel to connect to a remote manual endpoint.

        [manual client] <- manual -> [vanilla client] <- quic datagram -> [vanilla server] <- manual -> [manual server]

    */
    TEST_CASE("011 - Manual Transmission: Binary endpoints", "[011][manual][binary]")
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

        opt::enable_datagrams enable_dgrams{};

        dgram_data_callback vanilla_client_recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte> data) {
            manual_client->manually_receive_packet(Packet{Path{manual_client_addr, manual_server_addr}, std::move(data)});
        };

        dgram_data_callback vanilla_server_recv_dgram_cb = [&](dgram_interface&, std::vector<std::byte> data) {
            manual_server->manually_receive_packet(Packet{Path{manual_server_addr, manual_client_addr}, std::move(data)});
        };

        opt::manual_routing manual_client_sender{
                [&](const Path&, bspan d) { vanilla_client_ci->send_datagram(std::vector<std::byte>{d.begin(), d.end()}); }};

        opt::manual_routing manual_server_sender{
                [&](const Path&, bspan d) { vanilla_server_ci->send_datagram(std::vector<std::byte>{d.begin(), d.end()}); }};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        vanilla_server = test_net.endpoint(
                vanilla_server_addr, vanilla_server_established, enable_dgrams, vanilla_server_recv_dgram_cb);
        vanilla_client = test_net.endpoint(
                vanilla_client_addr, vanilla_client_established, enable_dgrams, vanilla_client_recv_dgram_cb);
        manual_client = test_net.endpoint(manual_client_addr, manual_client_sender, manual_client_established);
        manual_server = test_net.endpoint(manual_server_addr, manual_server_sender, manual_server_established);

        REQUIRE_NOTHROW(vanilla_server->listen(server_tls));
        REQUIRE_NOTHROW(manual_server->listen(server_tls));

        RemoteAddress vanilla_client_remote{defaults::SERVER_PUBKEY, LOCALHOST, vanilla_server->local().port()};

        vanilla_client_ci = vanilla_client->connect(vanilla_client_remote, client_tls);

        CHECK(vanilla_client_established.wait());
        CHECK(vanilla_server_established.wait());

        std::this_thread::sleep_for(25ms);

        vanilla_server_ci = vanilla_server->get_all_conns(Direction::INBOUND).front();

        CHECK(vanilla_server_ci);

        std::this_thread::sleep_for(25ms);

        RemoteAddress manual_client_remote{defaults::SERVER_PUBKEY, manual_server_addr};

        manual_client_ci = manual_client->connect(manual_client_remote, client_tls);

        CHECK(manual_client_established.wait());
        CHECK(manual_server_established.wait());
    }
}  //  namespace oxen::quic::test
