/*
    Test server binary
*/

#include <sodium/crypto_generichash_blake2b.h>
#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <thread>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string key{"./serverkey.pem"}, cert{"./servercert.pem"};

    cli.add_option("-c,--certificate", cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-k,--key", key, "Path to server key to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    // TODO: make this optional
    std::string client_cert{"./clientcert.pem"};
    cli.add_option("-C,--clientcert", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network server_net{};

    opt::server_tls server_tls{key, cert, client_cert};

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    opt::local_addr server_local{listen_addr, listen_port};

    auto stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id);
        return 0;
    };

    struct stream_info {
        explicit stream_info(uint64_t expected) : expected{expected} {
            crypto_generichash_blake2b_init(&hasher, nullptr, 0, 32);
        }

        uint64_t expected;
        uint64_t received = 0;
        crypto_generichash_blake2b_state hasher;
    };

    std::unordered_map<ConnectionID, std::map<int64_t, stream_info>> csd;
    auto stream_data = [&](Stream& s, bstring_view data) {
        auto& sd = csd[s.conn.source_cid];
        auto it = sd.find(s.stream_id);
        if (it == sd.end()) {
            if (data.size() < sizeof(uint64_t)) {
                log::critical(test_cat, "Well this was unexpected: I got {} < 8 bytes", data.size());
                return;
            }
            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            data.remove_prefix(sizeof(uint64_t));
            it = sd.emplace(s.stream_id, size).first;
            log::warning(test_cat, "First data from new stream {}, expecting {}B!", s.stream_id, size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;
        info.received += data.size();
        if (info.received > info.expected) {
            log::critical(test_cat, "Received too much data ({}B > {}B)!");
            if (!need_more)
                return;
            data.remove_suffix(info.received - info.expected);
        }
        crypto_generichash_blake2b_update(
            &info.hasher, reinterpret_cast<const unsigned char*>(data.data()), data.size());

        if (info.received >= info.expected) {
            std::basic_string<unsigned char> final_hash;
            final_hash.resize(32);
            crypto_generichash_blake2b_final(&info.hasher, final_hash.data(), 32);

            log::warning(test_cat, "Data from stream {} complete ({} B).  Final hash: {}",
                    s.stream_id, info.received, oxenc::to_hex(final_hash.begin(), final_hash.end()));

            s.send(std::move(final_hash));
        }
    };

    log::debug(test_cat, "Calling 'server_listen'...");
    auto server = server_net.server_listen(server_local, server_tls, stream_opened, stream_data);

    log::debug(test_cat, "Starting event loop thread...");
    auto [ev_thread, running, done] = spawn_event_loop(server_net);

    while (done.wait_for(3s) != std::future_status::ready)
        log::info(test_cat, "waiting...");

    ev_thread.join();

    return 0;
}
