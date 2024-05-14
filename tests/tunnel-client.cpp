/*
    Tunnel client binary
*/

#include "tcp.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC tunneled test client"};
    std::string log_file = "stderr", log_level = "info";

    add_log_opts(cli, log_file, log_level);

    int num_conns{2};
    cli.add_option("-N,--num-conns", num_conns, "Number of remote server TCP backends for which to set up listeners (1/2/3)")
            ->check(CLI::Range(1, 3));

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network client_net{};

    auto client_tls = GNUTLSCreds::make_from_ed_keys(TUNNEL_SEED, TUNNEL_PUBKEY);

    Address tunnel_client_local{LOCALHOST, 1111}, manual_client_local{LOCALHOST, 2222}, tunnel_server_local{LOCALHOST, 3333};

    Address localhost_blank{LOCALHOST, 0};

    // Remote manual server addresses
    std::vector<Address> remote_addrs{{LOCALHOST, 4444}, {LOCALHOST, 4455}, {LOCALHOST, 4466}};

    std::atomic<int> current_conn{0};

    std::vector<std::promise<void>> conn_proms{};
    std::vector<std::future<void>> conn_futures{};

    for (int i = 0; i < num_conns; ++i)
    {
        conn_proms.push_back(std::promise<void>{});
        conn_futures.push_back(conn_proms.back().get_future());
    }

    // Connectable addresses
    std::vector<RemoteAddress> connect_addrs{};

    for (auto& r : remote_addrs)
        connect_addrs.push_back(RemoteAddress{TUNNEL_PUBKEY, r});

    // Paths from manual client to remote manual server keyed to remote port
    std::unordered_map<uint16_t, Path> paths;

    for (auto& r : remote_addrs)
        paths.emplace(r.port(), Path{localhost_blank, r});

    /** key: remote address to which we are connecting
        value: tunneled quic connection
    */
    std::unordered_map<Address, tunneled_connection> _tunnels;

    auto manual_client_established = [&](connection_interface& ci) {
        auto path = ci.path();
        auto& remote = path.remote;

        auto _handle = TCPHandle::make_server(
                client_net.loop(), [&, p = path](struct bufferevent* _bev, evutil_socket_t _fd, Address src) {
                    auto& remote = p.remote;

                    if (auto it_a = _tunnels.find(remote); it_a != _tunnels.end())
                    {
                        auto& conns = it_a->second.conns;

                        if (auto it_b = conns.find(remote.port()); it_b != conns.end())
                        {
                            auto& tcp_quic = it_b->second;
                            auto& ci = tcp_quic._ci;

                            log::info(test_cat, "Opening stream...");
                            // data and close cb set after lambda execution
                            auto s = ci->open_stream();

                            log::info(test_cat, "Opening TCPConnection...");

                            auto tcp_conn = std::make_shared<TCPConnection>(_bev, _fd, std::move(s));

                            if (tcp_conn->is_tunnel_initiator != true)
                                throw std::runtime_error{"Tunnel client should have tunnel_initiator set to TRUE"};

                            auto [it, _] = tcp_quic._tcp_conns[src].insert(std::move(tcp_conn));

                            return it->get();
                        }
                        throw std::runtime_error{"Could not find paired TCP-QUIC for remote port:{}"_format(remote.port())};
                    }
                    throw std::runtime_error{"Could not find tunnel to remote:{}!"_format(remote)};
                });

        if (not _handle->is_bound())
            throw std::runtime_error{"Failed to bind TCP Handle listener!"};

        auto bind = *_handle->bind();

        log::info(
                test_cat,
                "Manual client established connection (path: {}); assigned TCPHandle listening on: {}",
                path,
                bind);

        tunneled_connection tunneled_conn{};
        tunneled_conn.h = std::move(_handle);

        TCPQUIC tcp_quic{};
        tcp_quic._ci = ci.shared_from_this();

        if (auto [_, b] = tunneled_conn.conns.emplace(remote.port(), std::move(tcp_quic)); not b)
            throw std::runtime_error{"Failed to emplace tunneled_connection!"};

        _tunnels.emplace(remote, std::move(tunneled_conn));

        if (current_conn >= num_conns)
            throw std::runtime_error{
                    "Client cannot accept more than configured number ({}) of connections!"_format(num_conns)};

        conn_proms[current_conn].set_value();
        current_conn += 1;
    };

    try
    {
        std::shared_ptr<connection_interface> tunnel_ci;

        auto manual_client = client_net.endpoint(localhost_blank, opt::manual_routing{[&](const Path& p, bstring_view data) {
                                                     tunnel_ci->send_datagram(serialize_payload(data, p.remote.port()));
                                                 }});

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring buf) {
            auto [p, data] = deserialize_payload(std::move(buf));

            if (auto it = paths.find(p); it != paths.end())
                manual_client->manually_receive_packet(Packet{it->second, data});
            else
                throw std::runtime_error{"Could not find path for route to remote port:{}"_format(p)};
        };

        auto tunnel_client_established = callback_waiter{
                [&](connection_interface&) { log::info(test_cat, "Tunnel client established connection to remote!"); }};

        auto tunnel_client =
                client_net.endpoint(tunnel_client_local, recv_dgram_cb, opt::enable_datagrams{Splitting::ACTIVE});

        RemoteAddress tunnel_server_addr{TUNNEL_PUBKEY, tunnel_server_local};

        log::info(test_cat, "Connecting tunnel client to server...");

        tunnel_ci = tunnel_client->connect(tunnel_server_addr, client_tls, opt::keep_alive{10s}, tunnel_client_established);
        tunnel_client_established.wait();

        for (int i = 0; i < num_conns; ++i)
        {
            manual_client->connect(connect_addrs[i], client_tls, manual_client_established, opt::keep_alive{10s});

            conn_futures[i].wait();
        }

        auto msg = "Client established {} tunneled connections:\n\n"_format(current_conn.load());

        for (auto& [addr, tun] : _tunnels)
            msg += "\tTCP Listener: {} --> Remote: {}\n"_format(*tun.h->bind(), addr);

        log::critical(test_cat, "{}", msg);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start client: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
