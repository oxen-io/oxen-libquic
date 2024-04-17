/*
    Speedtest binary
*/

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "speedtest-server.hpp"
#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);
    std::string seed;
    add_seed_opt(cli, seed);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    Address server_local{listen_addr, listen_port};

    speedtest::Server server{seed, server_local};

    for (;;)
        std::this_thread::sleep_for(10min);
}
