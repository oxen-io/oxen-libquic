/*
    Test server binary
*/

#include "utils.hpp"

#include <oxen/quic/opt.hpp>

#include <fmt/ranges.h>

#include <random>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest server"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_addr = DEFAULT_SPEEDTEST_ADDR.to_string();
    std::string seed_string;
    bool enable_0rtt;
    bool disable_pmtud;
    common_server_opts(cli, server_addr, seed_string, enable_0rtt, disable_pmtud);

    bool verify_datagrams = false;
    cli.add_flag("-V,--verify-datagrams", verify_datagrams, "Verify the value of each received datagrams");

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

    auto SPEEDTEST = log::Cat("SPEEDTEST");
    log::set_level(SPEEDTEST, log::Level::info);

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        server_tls->enable_inbound_0rtt();

    auto server_local = Address::parse(server_addr, DEFAULT_SPEEDTEST_ADDR.port());

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct stream_info
    {
        uint64_t expected;
        uint64_t received = 0;
    };

    std::map<ConnectionID, std::map<int64_t, stream_info>> csd;

    stream_data_callback stream_data = [&](Stream& s, std::span<const std::byte> data) {
        auto& sd = csd[s.reference_id];

        auto it = sd.find(s.stream_id());
        if (it == sd.end())
        {
            if (data.size() < sizeof(uint64_t))
            {
                log::error(
                        SPEEDTEST,
                        "Unexpected initial stream data on {}:{}: received {} < 8 bytes",
                        s.reference_id,
                        s.stream_id(),
                        data.size());
                return;
            }

            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            data = data.subspan(sizeof(uint64_t));

            it = sd.emplace(s.stream_id(), size).first;
            log::info(SPEEDTEST, "First data from new stream {}:{}, expecting {}B!", s.reference_id, s.stream_id(), size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;
        info.received += data.size();
        if (info.received > info.expected)
        {
            log::error(
                    SPEEDTEST,
                    "Received too much data on stream {}:{}: ({}B > {}B)!",
                    s.reference_id,
                    s.stream_id(),
                    info.received,
                    info.expected);
            if (!need_more)
                return;
            data = data.first(data.size() - (info.received + info.expected));
        }

        if (info.received >= info.expected)
        {
            log::info(SPEEDTEST, "Data from stream {}:{} complete ({} B).", s.reference_id, s.stream_id(), info.received);
            s.send("\x00"s);
        }
    };

    struct recv_info
    {
        uint64_t n_expected = 0;
        uint64_t n_received = 0;
        size_t last_dgram_size = 0;
        bool ping = false;
    };

    std::unordered_map<ConnectionID, recv_info> conn_dgram_data;

    std::vector<std::byte> dgram_rainbow;
    dgram_rainbow.resize(5000);
    for (size_t i = 0; i < dgram_rainbow.size(); i++)
        dgram_rainbow[i] = static_cast<std::byte>(i % 256);

    auto flake = [rng = std::mt19937_64{std::random_device{}()},
                  flake = std::bernoulli_distribution{flakiness},
                  &flakiness]() mutable -> bool { return flakiness > 0 ? flake(rng) : false; };

    dgram_data_callback recv_dgram_cb = [&](datagram&& dg) {
        auto& dgram_data = conn_dgram_data[dg.conn.reference_id()];

        const auto size = dg.data.size();

        if (dgram_data.n_expected == 0 && size == 4)
        {
            dgram_data.ping = true;
            dgram_data.n_expected = -1;
        }
        if (dgram_data.ping)
        {
            if (size != 4)
            {
                log::error(test_cat, "Received invalid ping datagram of size {} (expected 4 bytes); ignoring", size);
                return;
            }
            auto ping_num = oxenc::load_little_to_host<uint32_t>(dg.data.data());
            if (flake())
                log::debug(test_cat, "received ping {} but simulating flakiness and not replying", ping_num);
            else
            {
                log::debug(test_cat, "received ping {}, reflecting it", ping_num);
                dg.datagrams.send(std::move(dg).extract());
            }
            return;
        }

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

            dg.datagrams.send("DONE!"s);
        }
    };

    Loop loop;
    std::shared_ptr<Endpoint> server;
    try
    {
        std::optional<opt::disable_mtu_discovery> mtu;
        if (disable_pmtud)
            mtu.emplace();

        log::debug(test_cat, "Starting up endpoint");
        server = Endpoint::endpoint(
                loop,
                server_local,
                generate_static_secret(seed_string),
                opt::inbound_alpn("speedtests"),
                mtu,
                opt::enable_datagrams{Splitting::ACTIVE});
        server->listen(server_tls, stream_opened, stream_data, recv_dgram_cb);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    server_log_listening(server_local, DEFAULT_SPEEDTEST_ADDR, pubkey, seed_string, enable_0rtt);

    for (;;)
        std::this_thread::sleep_for(10min);
}
