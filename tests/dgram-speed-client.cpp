/*
    Test client binary
*/

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC datagram speedtest client"};

    std::string local_addr, remote_pubkey, seed_string;
    auto remote_addr = DEFAULT_DGRAM_SPEED_ADDR.to_string();
    bool enable_0rtt;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, enable_0rtt, zerortt_path);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    uint64_t size = 1'000'000'000;
    cli.add_option("-S,--size", size, "Amount of data to transfer.");

    size_t dgram_size = 0;
    cli.add_option("--dgram-size", dgram_size, "Datagram size to send");

    int lookahead = -1;
    cli.add_option("--lookahead", lookahead, "Split datagram small packet lookahead; -1 uses the default value.");

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    struct send_data
    {
        std::shared_ptr<Stream> stream;
        std::atomic<bool> active = false;
        std::vector<std::byte> msg{};
        uint64_t size;
        uint64_t dgram_size;
        uint64_t n_iter;
        std::atomic<bool> is_sending = false;
        std::atomic<bool> is_done = false;
        std::promise<void> run_prom;
        std::future<void> running = run_prom.get_future();
        std::atomic<bool> failed = false;

        send_data(uint64_t _total_size, uint64_t _dgram_size) :
                size{_total_size}, dgram_size{_dgram_size}, n_iter{size / dgram_size + 1}
        {
            log::warning(test_cat, "Preparing to send {} datagrams of max size {}", n_iter, size);

            // Oversized message that should be big enough for any datagram size.  We send subspans
            // of this starting at [1]...[250] for all but the last one (the last one starts at [0]
            // and has initial byte 0, which the server uses to identify the last packet), to help
            // identify in trace logging which packet could be going wrong.
            msg.resize(5000);
            for (uint64_t i = 0; i < msg.size(); i++)
                msg[i] = static_cast<std::byte>(i % 256);
        }

        std::span<const std::byte> data(size_t pkt_i) { return std::span{msg}.subspan(1 + pkt_i % 250, dgram_size); }
        std::span<const std::byte> final_data() { return std::span{msg}.subspan(0, dgram_size); }
    };

    std::optional<send_data> dgram_data;

    setup_logging(log_file, log_level);

    Network client_net{};

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    stream_close_callback stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id() >> 2;
        log::critical(test_cat, "Stream {} (rawid={}) closed (error={})", i, s.stream_id(), errcode);
    };

    dgram_data_callback recv_dgram_cb = [&](dgram_interface, std::span<const std::byte> data) {
        log::critical(test_cat, "Calling endpoint receive datagram callback... data received...");

        if (dgram_data->is_sending)
        {
            log::error(test_cat, "Got a datagram response ({}B) before we were done sending data!", data.size());
            dgram_data->failed = true;
        }
        else if (data.size() != 5)
        {
            log::error(test_cat, "Got unexpected data from the other side: {}B != 5B", data.size());
            dgram_data->failed = true;
        }
        else if (data != "DONE!"_bsp)
        {
            log::error(
                    test_cat,
                    "Got unexpected data: expected 'DONE!', got (hex): '{}'",
                    oxenc::to_hex(data.begin(), data.end()));
            dgram_data->failed = true;
        }
        else
        {
            dgram_data->failed = false;
            log::critical(test_cat, "All done, hurray!\n");
        }

        dgram_data->is_done = true;
        dgram_data->run_prom.set_value();
    };

    Address client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = Address{a, p};
    }

    auto client_established = callback_waiter{[](connection_interface&) {}};

    auto [server_a, server_p] = parse_addr(remote_addr);
    RemoteAddress server_addr{remote_pubkey, server_a, server_p};
    opt::enable_datagrams split_dgram(Splitting::ACTIVE);

    log::critical(test_cat, "Calling 'client_connect'...");
    auto client = client_net.endpoint(
            client_local,
            client_established,
            recv_dgram_cb,
            split_dgram,
            generate_static_secret(seed_string),
            opt::alpns{"dgram-speed"});
    auto client_ci = client->connect(server_addr, client_tls, stream_closed);

    client_ci->set_split_datagram_lookahead(lookahead);

    if (!client_established.wait())
    {
        log::critical(log_cat, "Connection timed out!");
        return 1;
    }

    uint64_t max_size =
            std::max<uint64_t>((dgram_size == 0) ? client_ci->get_max_datagram_size() : dgram_size, sizeof(uint8_t));

    dgram_data.emplace(size, max_size);

    std::vector<std::byte> remaining_str;
    remaining_str.resize(8);
    oxenc::write_host_as_little(dgram_data->n_iter, remaining_str.data());
    log::warning(test_cat, "Sending datagram count to remote...");
    client_ci->send_datagram(remaining_str, nullptr);

    std::chrono::steady_clock::time_point started_at;

    dgram_data->is_sending = true;
    log::warning(test_cat, "Sending payload to remote...");

    started_at = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < dgram_data->n_iter - 1; ++i)
    {
        // Just send these with the 0 at the beginning
        client_ci->send_datagram(dgram_data->data(i), nullptr);
    }
    // Send a final one always using i = 0 so that we get the bit of the data starting with the
    // terminal 0 byte value.
    client_ci->send_datagram(dgram_data->final_data(), nullptr);

    log::warning(test_cat, "Client done sending payload to remote!");
    dgram_data->is_sending = false;

    dgram_data->running.get();

    auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
    fmt::print("Elapsed time: {:.5f}s\n", elapsed);
    fmt::print("Speed: {:.5f}MB/s\n", size / 1'000'000.0 / elapsed);

    return 0;
}
