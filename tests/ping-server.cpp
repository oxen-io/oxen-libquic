/*
    Ping server binary
*/

#include "utils.hpp"

#include <oxen/quic/gnutls_crypto.hpp>
#include <oxenc/endian.h>

#include <CLI/Validators.hpp>

#include <gnutls/gnutls.h>

#include <random>

using namespace oxen::quic;

namespace oxen::quic
{
    GNUTLSCreds::anti_replay_add_cb default_anti_replay_add();
}

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC ping server"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_addr = DEFAULT_PING_ADDR.to_string();
    std::string seed_string;
    bool enable_0rtt;
    common_server_opts(cli, server_addr, seed_string, enable_0rtt);

    double flakiness = 0.0;
    cli.add_option("-f,--flakiness", flakiness, "Fail to respond to pings this proportion of the time.")
            ->capture_default_str()
            ->expected(0.0, 1.0);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    Network server_net{};

    auto server_local = Address::parse(server_addr, DEFAULT_PING_ADDR.port());

    std::shared_ptr<Endpoint> server;

    auto conn_established = [&](connection_interface& ci) {
        log::info(test_cat, "Incoming connection established from {}", ci.remote());
    };

    auto conn_closed = [&](connection_interface& ci, uint64_t) {
        log::info(test_cat, "Connection from {} closed", ci.remote());
    };

    auto flake = [rng = std::mt19937_64{std::random_device{}()},
                  flake = std::bernoulli_distribution{flakiness},
                  &flakiness]() mutable -> bool { return flakiness > 0 ? flake(rng) : false; };
    auto dgram_recv = [&](dgram_interface& d, std::vector<std::byte> in) {
        if (in.size() != 4)
        {
            log::error(test_cat, "Received invalid ping datagram of size {} (expected 4 bytes); ignoring", in.size());
            return;
        }
        auto ping_num = oxenc::load_little_to_host<uint32_t>(in.data());
        if (flake())
            log::debug(test_cat, "received ping {} but simulating flakiness and not replying", ping_num);
        else
        {
            log::debug(test_cat, "received ping {}, reflecting it", ping_num);
            d.reply(std::move(in));
        }
    };

    try
    {
        log::info(test_cat, "Starting endpoint...");
        if (enable_0rtt)
            server_tls->enable_inbound_0rtt();

        server = server_net.endpoint(
                server_local,
                conn_established,
                conn_closed,
                opt::enable_datagrams{},
                generate_static_secret(seed_string),
                opt::alpns{"quic-ping"});
        server->listen(server_tls, dgram_recv);

        server_log_listening(server_local, DEFAULT_PING_ADDR, pubkey, seed_string, enable_0rtt);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
