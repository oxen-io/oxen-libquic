/*
    Test server binary
*/

#include "utils.hpp"

using namespace oxen::quic;

inline std::string_view view(std::span<const std::byte> x)
{
    return {reinterpret_cast<const char*>(x.data()), x.size()};
}

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC datagram speedtest server"};

    auto server_addr = DEFAULT_DGRAM_SPEED_ADDR.to_string();
    std::string seed_string;
    bool enable_0rtt, disable_pmtud;
    common_server_opts(cli, server_addr, seed_string, enable_0rtt, disable_pmtud);

    bool verify_datagrams = false;
    cli.add_flag("-V,--verify-datagrams", verify_datagrams, "Verify the value of each received datagrams");

    bool shutdown_on_error = false;
    cli.add_flag(
            "--shutdown",
            shutdown_on_error,
            "Stop the server after a non-perfect fidelity or datagram verification failure");

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

    setup_logging(log_file, log_level);

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        server_tls->enable_inbound_0rtt();

    Network server_net{};

    auto server_local = Address::parse(server_addr, DEFAULT_DGRAM_SPEED_ADDR.port());

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct recv_info
    {
        uint64_t n_expected = 0;
        uint64_t n_received = 0;
        size_t last_dgram_size = 0;
    };

    std::unordered_map<ConnectionID, recv_info> conn_dgram_data;

    std::shared_ptr<Endpoint> server;

    std::atomic<bool> shutdown{false};

    std::vector<std::byte> dgram_rainbow;
    dgram_rainbow.resize(5000);
    for (size_t i = 0; i < dgram_rainbow.size(); i++)
        dgram_rainbow[i] = static_cast<std::byte>(i % 256);

    dgram_data_callback recv_dgram_cb = [&](datagram&& dg) {
        auto& dgram_data = conn_dgram_data[dg.conn.reference_id()];

        const auto size = dg.data.size();
        if (size != dgram_data.last_dgram_size)
        {
            log::warning(
                    test_cat, "Received a changed datagram size {}; last datagram was {}", size, dgram_data.last_dgram_size);
            dgram_data.last_dgram_size = size;
        }

        if (dgram_data.n_expected == 0)
        {
            // The very first packet should be 8 bytes containing the uint64_t count of total
            // packets being sent, not including this initial one.
            if (size != 8)
                log::error(test_cat, "Invalid initial packet: expected 8-byte test size, got {} bytes", size);
            auto count = oxenc::load_little_to_host<uint64_t>(dg.data.data());
            dgram_data.n_expected = count;
            log::warning(
                    test_cat,
                    "First data from new connection {} datagram channel, expecting {} datagrams!",
                    dg.conn.remote(),
                    dgram_data.n_expected);
            return;
        }

        // The final packet starts with a \x00; up until then we get starts from 1,2,...250,1,2,...,250,1,2,...
        const bool done = dg.data[0] == std::byte{0};

        auto& info = dgram_data;

        if (verify_datagrams)
        {
            // The first byte value is itself the rainbow offset, and goes 1->250 repeatedly until
            // the final packet, which has initial byte 0:
            size_t offset = static_cast<uint8_t>(dg.data[0]);
            bool bad = false;
            if (offset > 250)
            {
                bad = true;
                log::error(log_cat, "Datagram {} verification found invalid first byte value {}", info.n_received, offset);
            }
            else if (view(dg.data) != view(std::span{dgram_rainbow}.subspan(offset, size)))
            {
                bad = true;
            }
            if (bad)
            {
                log::error(
                        test_cat,
                        "Datagram {} verification failed: expected byte rainbow, received {}",
                        info.n_received,
                        buffer_printer{dg.data});
                if (shutdown_on_error)
                    shutdown = true;
            }
        }

        bool need_more = info.n_received < info.n_expected;
        info.n_received++;

        if (info.n_received > info.n_expected)
        {
            log::critical(test_cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);

            if (!need_more)
                return;
        }

        if (done)
        {
            auto reception_rate = ((float)info.n_received / (float)info.n_expected) * 100;

            log::critical(
                    test_cat,
                    "Datagram test complete for {}. Fidelity: {}\% ({} received of {} expected)",
                    dg.conn.remote(),
                    reception_rate,
                    info.n_received,
                    info.n_expected);

            if (shutdown_on_error && info.n_received < info.n_expected)
                shutdown = true;

            dg.datagrams.send("DONE!"s);
        }
    };

    try
    {
        log::debug(test_cat, "Starting up endpoint");
        auto split_dgram = opt::enable_datagrams(Splitting::ACTIVE);
        std::optional<opt::disable_mtu_discovery> mtu;
        if (disable_pmtud)
            mtu.emplace();
        server = server_net.endpoint(
                server_local,
                recv_dgram_cb,
                split_dgram,
                generate_static_secret(seed_string),
                opt::alpns{"dgram-speed"},
                mtu);
        server->listen(server_tls, stream_opened);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    server_log_listening(server_local, DEFAULT_DGRAM_SPEED_ADDR, pubkey, seed_string, enable_0rtt);

    while (!shutdown)
        std::this_thread::sleep_for(100ms);
}
