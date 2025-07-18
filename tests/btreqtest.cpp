/*
 * Connects to a quic server, sends bt stream data, and waits for the response.
 */

#include "oxen/quic/opt.hpp"
#include "utils.hpp"

#include <gnutls/crypto.h>

#include <chrono>
#include <vector>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest client"};

    std::string local_addr, remote_addr, remote_pubkey, seed_string;
    bool enable_0rtt, disable_pmtud;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, disable_pmtud, enable_0rtt, zerortt_path);

    std::string alpn;
    cli.add_option("-a,--alpn", alpn, "Client ALPN to use when negotiating the connection")->required();

    std::vector<std::string> commands;
    cli.add_option("commands", commands, "Pairs of endpoint and body values to send.  Each pair makes one request")
            ->required()
            ->expected(2, -1);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    if (commands.size() % 2)
    {
        std::cerr << "Invalid commands: expected even number of command/body pairs\n";
        return 1;
    }

    setup_logging(log_file, log_level);

    Loop loop;

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    Address client_local{};
    if (!local_addr.empty())
        client_local = Address::parse(local_addr);

    RemoteAddress server_addr{remote_pubkey, Address::parse(remote_addr)};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    std::optional<opt::disable_mtu_discovery> mtu;
    if (disable_pmtud)
        mtu.emplace();

    auto client =
            Endpoint::endpoint(loop, client_local, generate_static_secret(seed_string), opt::outbound_alpns{{alpn}}, mtu);
    log::info(test_cat, "Connecting to {}...", server_addr);
    auto conn = client->connect(server_addr, client_tls);

    auto s = conn->open_stream<BTRequestStream>();

    for (auto it = commands.begin(); it != commands.end();)
    {
        const auto& ep = *it++;
        const auto& body = *it++;
        log::info(test_cat, "Sending {} request...", ep);
        auto sent = std::chrono::steady_clock::now();
        std::promise<void> prom;
        s->command(ep, body, [&sent, &ep, &prom](message m) {
            double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - sent).count();

            if (m)
            {
                log::info(test_cat, "Received {}-byte {} response in {:.3f}s", m.body().size(), ep, elapsed);
                std::cout << m.body();
            }
            else if (m.timed_out)
                log::warning(test_cat, "Request {} timed out in {:.3f}s", ep, elapsed);
            else
                log::warning(test_cat, "Request {} errored in {:.3f}s: {}", ep, elapsed, m.body());
            prom.set_value();
        });
        prom.get_future().wait();
    }

    return 0;
}
