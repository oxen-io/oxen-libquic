/*
    Ping client binary
*/

#include "signal.h"
#include "utils.hpp"

#include <oxen/quic/gnutls_crypto.hpp>
#include <oxenc/bt_serialize.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>

#include <gnutls/gnutls.h>

#include <filesystem>
#include <limits>

using namespace oxen::quic;

struct ping_stats
{
    uint32_t sent, received;
    double rtt_sum, rtt_sumsq, rtt_min = std::numeric_limits<double>::infinity(),
                               rtt_max = -std::numeric_limits<double>::infinity();
};

ping_stats run_client(
        std::string_view remote_addr,
        std::string_view remote_pubkey,
        std::string_view local_addr,
        std::string_view seed_string,
        bool enable_0rtt,
        const std::filesystem::path& zerortt_path,
        uint32_t ping_count,
        double ping_interval,
        double ping_timeout,
        bool reconnect);

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC ping client"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string local_addr, remote_pubkey, seed_string;
    auto remote_addr = DEFAULT_PING_ADDR.to_string();
    bool enable_0rtt;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, enable_0rtt, zerortt_path);

    double ping_timeout = 5.0;
    cli.add_option(
               "-W,--timeout",
               ping_timeout,
               "How long to wait for the final ping reply (when using -c) before giving up and disconnecting without it.")
            ->capture_default_str();

    uint32_t ping_count = 0;
    double ping_interval = 1.0;
    cli.add_option("-c,--count", ping_count, "Number of pings to send to the server.  0 to ping forever.")
            ->capture_default_str();
    cli.add_option("-i,--interval", ping_interval, "Interval (in seconds) between subsequent pings.")->capture_default_str();

    bool reconnect = false;
    cli.add_flag(
            "-r,--reconnect",
            reconnect,
            "Automatically reconnect upon connection closing (such as from interruption).  Without this option a connection "
            "close for any reason terminates the ping.");
    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto startup = std::chrono::steady_clock::now();

    auto stats = run_client(
            remote_addr,
            remote_pubkey,
            local_addr,
            seed_string,
            enable_0rtt,
            zerortt_path,
            ping_count,
            ping_interval,
            ping_timeout,
            reconnect);

    fmt::print(
            "\n\n\n\nPing results: {} sent, {} received ({:.3f}%) in {}\n",
            stats.sent,
            stats.received,
            100.0 * stats.received / stats.sent,
            friendly_duration(std::chrono::steady_clock::now() - startup));

    if (stats.received > 0)
    {
        double mean = stats.rtt_sum / stats.received;
        double sstdev;
        if (stats.received > 1)
        {
            double var = (stats.rtt_sumsq - stats.received * mean * mean) / (stats.received - 1);
            sstdev = std::sqrt(var);
        }
        fmt::print(
                "RTT mean: {}, stdev: {}, min: {}, max: {}\n",
                friendly_duration(std::chrono::nanoseconds{static_cast<int64_t>(mean * 1e9)}),
                stats.received <= 1 ? "N/A"
                                    : friendly_duration(std::chrono::nanoseconds{static_cast<int64_t>(sstdev * 1e9)}),
                friendly_duration(std::chrono::nanoseconds{static_cast<int64_t>(stats.rtt_min * 1e9)}),
                friendly_duration(std::chrono::nanoseconds{static_cast<int64_t>(stats.rtt_max * 1e9)}));
    }
    fmt::print("\n\n\n");
}

ping_stats run_client(
        std::string_view remote_addr,
        std::string_view remote_pubkey,
        std::string_view local_addr,
        std::string_view seed_string,
        bool enable_0rtt,
        const std::filesystem::path& zerortt_path,
        uint32_t ping_count,
        double ping_interval_d,
        double ping_timeout,
        bool reconn)
{
    // Block signals in this thread (and new threads we create); we set up a dedicated thread for
    // signal handling below.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR2);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    ping_stats stats{};

    Network client_net{};

    std::atomic<bool> reconnect{reconn};

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    Address client_local{};
    if (!local_addr.empty())
        client_local = Address::parse(local_addr);

    std::optional<std::promise<void>> all_done;
    std::shared_ptr<Ticker> ticker;
    std::chrono::steady_clock::time_point started, established;

    auto conn_established = [&](connection_interface& ci) {
        established = get_time();
        log::info(test_cat, "Connection established to {} in {}", ci.remote(), friendly_duration(established - started));
    };

    auto conn_closed = [&](connection_interface& ci, uint64_t) {
        log::info(test_cat, "Disconnected from {}", ci.remote());

        all_done->set_value();
    };

    auto server_addr = Address::parse(remote_addr, DEFAULT_PING_ADDR.port());

    log::info(test_cat, "Constructing endpoint on {}", client_local);

    std::vector<unsigned char> ep_secret;
    ep_secret.resize(32);
    sha3_256(ep_secret.data(), seed_string, "libquic-test-static-secret");

    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    auto client = client_net.endpoint(
            client_local,
            conn_established,
            conn_closed,
            opt::enable_datagrams{},
            generate_static_secret(seed_string),
            opt::alpns{"quic-ping"});

    auto sig_handler = std::async(std::launch::async, [wclient = std::weak_ptr{client}, &sigset, &reconnect]() {
        int signum = 0;
        sigwait(&sigset, &signum);
        while (signum != SIGUSR2)  // USR2 is how we gracefully signal this thread on normal exit
        {
            log::warning(test_cat, "Caught signal, disconnecting");
            reconnect = false;
            if (auto client = wclient.lock())
                client->close_conns();
            sigwait(&sigset, &signum);
        }
        return signum;
    });

    // Circular buffer so that we can calculate RTTs even if the responses arrive out of order.
    std::array<std::chrono::steady_clock::time_point, 100> sent_at;

    auto dgram_recv = [&](dgram_interface&, std::vector<std::byte> data) mutable {
        if (data.size() != 4)
        {
            log::error(test_cat, "Invalid ping response datagram; expected 4 bytes, got {}", data.size());
            return;
        }
        auto now = std::chrono::steady_clock::now();

        auto ping_num = oxenc::load_little_to_host<uint32_t>(data.data());
        stats.received++;
        auto ping_time = now - sent_at[ping_num % sent_at.size()];
        auto rtt = std::chrono::duration<double>{ping_time}.count();
        log::info(test_cat, "Ping {} received in {}", ping_num, friendly_duration(ping_time));
        stats.rtt_sum += rtt;
        stats.rtt_sumsq += rtt * rtt;
        if (rtt < stats.rtt_min)
            stats.rtt_min = rtt;
        if (rtt > stats.rtt_max)
            stats.rtt_max = rtt;

        if (ping_count && ping_num == ping_count - 1)
            client->close_conns();
    };

    log::info(test_cat, "Connecting to {}...", server_addr);

    std::shared_ptr<connection_interface> client_conn;

    bool multiping = false;
    std::chrono::nanoseconds ping_interval{static_cast<int64_t>(ping_interval_d * 1e9)};
    auto ping_wait = std::chrono::duration_cast<std::chrono::microseconds>(ping_interval);
    if (ping_wait < 1ms)
    {
        // If the ping interval is too small then the event loop will start bottlenecking how many
        // times the ticker actually gets called to less than the desired frequency, so instead for
        // a tiny interval we run on a 1ms timer and then figure out how many pings we should have
        // sent so far and send out however many are needed to catch up, all at once.
        ping_wait = 1ms;
        multiping = true;
    }

    std::optional<std::chrono::steady_clock::time_point> timeout;
    auto send_ping = [&] {
        auto now = get_time();
        uint32_t target = multiping ? std::max(now - established, 0ns) / ping_interval : stats.sent + 1;

        if (timeout)
        {
            if (now >= *timeout)
            {
                log::warning(test_cat, "Timeout waiting for final ping response; disconnecting");
                if (ticker)
                    ticker->stop();
                client_conn->close_connection();
            }
            return;
        }

        while (stats.sent < target && !timeout)
        {
            uint32_t ping_num = stats.sent++;
            if (ping_count && stats.sent == ping_count)
            {
                // This is our last ping, so switch into wait-for-timeout mode after this one
                timeout = get_time() + std::chrono::nanoseconds{static_cast<int64_t>(ping_timeout * 1e9)};
                reconnect = false;
            }

            std::string counter;
            counter.resize(sizeof(ping_num));
            oxenc::write_host_as_little(ping_num, counter.data());
            sent_at[ping_num % sent_at.size()] = std::chrono::steady_clock::now();
            client_conn->send_datagram(std::move(counter));
        }
    };

    auto last_start = std::chrono::steady_clock::now() - 2s;
    do
    {
        started = std::chrono::steady_clock::now();
        if (started < last_start + 1s)
        {
            // Cool down connection attempts to 1/s after a disconnect
            std::this_thread::sleep_for(25ms);
            continue;
        }
        last_start = started;
        all_done.emplace();
        client_conn = client->connect(RemoteAddress{remote_pubkey, server_addr}, dgram_recv, client_tls);

        send_ping();
        if (ticker)
            ticker->stop();
        ticker = client_net.call_every(ping_wait, send_ping);

        all_done->get_future().wait();
    } while (reconnect);

    kill(0, SIGUSR2);  // Wake up the signal handling thread to exit cleanly

    return stats;
}
