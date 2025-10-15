/*
    Test client binary
*/

#ifndef _WIN32
extern "C"
{
#include <signal.h>
#include <unistd.h>
}
#endif

#include "utils.hpp"

#include <random>
#include <span>
#include <vector>

namespace quic = oxen::quic;
using namespace quic;

using RNG = std::mt19937_64;

auto SPEEDTEST = log::Cat("SPEEDTEST");

struct stream_data
{
    std::shared_ptr<Stream> stream;
    size_t remaining;
    RNG rng;
    std::vector<std::vector<std::byte>> bufs;
    std::atomic<bool> done_sending = false;
    std::atomic<bool> done = false;
    std::promise<void> run_prom;
    std::future<void> running = run_prom.get_future();
    std::atomic<bool> failed = false;
    size_t next_buf = 0;

    stream_data() {}
    stream_data(size_t total_size, uint64_t seed, size_t chunk_size, size_t chunk_num) : remaining{total_size}, rng{seed}
    {
        bufs.resize(chunk_num);
        for (auto& buf : bufs)
            buf.resize(chunk_size);
    }
};

struct dgram_data_t
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

    dgram_data_t(uint64_t size, uint64_t dgram_size) : size{size}, dgram_size{dgram_size}, n_iter{size / dgram_size + 1}
    {
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

struct ping_stats
{
    uint32_t sent, received;
    double rtt_sum, rtt_sumsq, rtt_min = std::numeric_limits<double>::infinity(),
                               rtt_max = -std::numeric_limits<double>::infinity();
};
#ifndef _WIN32
sigset_t sigs;
#endif
ping_stats run_ping_client(
        const std::shared_ptr<Endpoint>& endpoint,
        const std::shared_ptr<GNUTLSCreds>& creds,
        const RemoteAddress& raddr,
        uint32_t ping_count,
        double ping_interval,
        double ping_timeout,
        bool ping_log,
        int stat_skip,
        bool reconnect);

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest client"};

    std::string local_addr, remote_addr = "127.0.0.1:5500"s, remote_pubkey, seed_string;
    bool enable_0rtt, disable_pmtud;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, disable_pmtud, enable_0rtt, zerortt_path);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    bool datagram = false;
    auto* dgopt = cli.add_flag("-d,--datagram", datagram, "Perform a datagram speedtest instead of a stream speedtest.");

    bool ping = false;
    cli.add_flag("-p,--ping", ping, "Ping the server rather than performing a stream speedtest")->excludes(dgopt);

    size_t parallel = 1;
    cli.add_option(
               "-j,--parallel", parallel, "Number of simultaneous streams to send (currently max 32).  Stream testing only.")
            ->check(CLI::Range(1, 32));

    uint64_t size = 1'000'000'000;
    cli.add_option(
            "-S,--size",
            size,
            "Amount of data to transfer (stream or datagram speedtest).  Defaults to 1GB.  When stream testing and using "
            "--parallel the data is divided equally across streams.");

    bool pregenerate = false;
    cli.add_flag("-g,--pregenerate", pregenerate, "Pregenerate all stream data in RAM before starting the test.");

    size_t chunk_size = 64_ki, chunk_num = 2;
    cli.add_option("--stream-chunk-size", chunk_size, "How much data to queue at once, per chunk");
    cli.add_option("--stream-chunks", chunk_num, "How much chunks to queue at once per stream")->check(CLI::Range(1, 100));

    size_t rng_seed = 0;
    cli.add_option(
            "--rng-seed",
            rng_seed,
            "RNG seed to use for stream data generation; with --parallel we use this, this+1, ... for the different "
            "threads.");

    size_t dgram_size = 0;
    cli.add_option("--dgram-size", dgram_size, "Datagram size to send for datagram speedtest");

    int lookahead = -1;
    cli.add_option(
            "--lookahead",
            lookahead,
            "Split datagram small packet lookahead for datagram speedtest; -1 uses the default value.");

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

    bool no_ping_log = false;
    cli.add_flag("--no-ping-log", no_ping_log, "Disable logging of ping responses");

    int ping_stat_skip = 0;
    cli.add_option(
            "--ping-stat-skip", ping_stat_skip, "Don't collect RTT stats for the first N responses (e.g. while connecting)");

    bool ping_reconnect = false;
    cli.add_flag(
            "-r,--ping-reconnect",
            ping_reconnect,
            "Automatically reconnect upon connection closing (such as from interruption) when running in ping mode.  "
            "Without this option a connection close for any reason terminates the ping.");

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    const bool stream = !datagram && !ping;

    setup_logging(log_file, log_level);

    log::set_level(SPEEDTEST, log::Level::info);

    if (ping)
    {
#ifndef _WIN32
        // Block signals in this thread (and new threads we create); we set up a dedicated thread
        // for signal handling in run_ping_client.
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGUSR2);
        sigaddset(&sigs, SIGINT);
        sigaddset(&sigs, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &sigs, nullptr);
#else
        log::critical(SPEEDTEST, "Speedtest ping client is currently not supported on Windows!");
        return 3;
#endif
    }

    Loop loop;

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    std::vector<std::unique_ptr<stream_data>> streams;
    streams.reserve(parallel);

    stream_close_callback stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id() >> 2;
        auto error = (errcode == STREAM_ERROR_CONNECTION_CLOSED || !errcode) ? ""s : " with error {}"_format(errcode);
        log::critical(test_cat, "Stream {} (rawid={}) closed{}", i, s.stream_id(), error);
    };

    stream_data_callback on_stream_data = [&](Stream& s, std::span<const std::byte> data) {
        size_t i = s.stream_id() >> 2;
        if (i >= parallel)
        {
            log::critical(
                    SPEEDTEST, "Something getting wrong: got unexpected stream id {}:{}", s.reference_id, s.stream_id());
            return;
        }

        auto& sd = *streams[i];
        if (sd.done)
        {
            log::error(
                    SPEEDTEST,
                    "Already got a confirmation byte from the other side of stream {}:{}, what is this nonsense‽",
                    s.reference_id,
                    s.stream_id());
            return;
        }

        if (!sd.done_sending)
        {
            log::error(
                    SPEEDTEST,
                    "Got a stream response on stream {}:{} of {}B before we were done sending data!",
                    s.reference_id,
                    s.stream_id(),
                    data.size());
            sd.failed = true;
        }
        else if (data.size() != 1 || data.front() != std::byte{0x00})
        {
            log::error(
                    test_cat,
                    "Got unexpected data from the other side: expected a single 0 byte, got {}B of data",
                    data.size());
            sd.failed = true;
        }

        sd.done = true;
        sd.run_prom.set_value();
    };

    std::optional<dgram_data_t> dgram_data;
    dgram_data_callback recv_dgram_cb = [&](quic::datagram dg) {
        log::critical(test_cat, "Calling endpoint receive datagram callback... data received...");

        if (dgram_data->is_sending)
        {
            log::error(test_cat, "Got a datagram response ({}B) before we were done sending data!", dg.data.size());
            dgram_data->failed = true;
        }
        else if (dg.data.size() != 5)
        {
            log::error(test_cat, "Got unexpected data from the other side: {}B != 5B", dg.data.size());
            dgram_data->failed = true;
        }
        else if (view(dg.data) != "DONE!"sv)
        {
            log::error(
                    test_cat,
                    "Got unexpected data: expected 'DONE!', got (hex): '{}'",
                    oxenc::to_hex(dg.data.begin(), dg.data.end()));
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
        client_local = Address::parse(local_addr);

    RemoteAddress server_addr{remote_pubkey, Address::parse(remote_addr, DEFAULT_SPEEDTEST_ADDR.port())};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    std::optional<opt::disable_mtu_discovery> mtu;
    if (disable_pmtud)
        mtu.emplace();

    auto client = Endpoint::endpoint(
            loop,
            client_local,
            generate_static_secret(seed_string),
            opt::outbound_alpn("speedtests"),
            mtu,
            opt::enable_datagrams{Splitting::ACTIVE});
    std::shared_ptr<Connection> client_ci;
    if (!ping)
    {
        log::info(SPEEDTEST, "Connecting to {}...", server_addr);
        client_ci = client->connect(server_addr, client_tls, on_stream_data, stream_closed, recv_dgram_cb);
        client_ci->set_split_datagram_lookahead(lookahead);
    }

    auto per_stream = size / parallel;

    auto gen_data = [](RNG& rng, size_t size, std::vector<std::byte>& data) {
        assert(size > 0);

        using rng_value = RNG::result_type;

        static_assert(
                RNG::min() == 0 && std::is_unsigned_v<rng_value> && RNG::max() == std::numeric_limits<rng_value>::max());

        constexpr size_t rng_size = sizeof(rng_value);
        const size_t rng_chunks = (size + rng_size - 1) / rng_size;
        const size_t size_data = rng_chunks * rng_size;

        // Generate some deterministic data from our rng; we're cheating a little here with the RNG
        // output value (which means this test won't be the same on different endian machines).
        data.resize(size_data);
        auto* rng_data = reinterpret_cast<rng_value*>(data.data());
        for (size_t i = 0; i < rng_chunks; i++)
            rng_data[i] = static_cast<rng_value>(rng());
        data.resize(size);
    };

    if (stream)
    {
        if (pregenerate)
            log::info(SPEEDTEST, "Pregenerating data...");

        for (size_t i = 0; i < parallel; i++)
        {
            uint64_t my_data = per_stream + (i == 0 ? size % parallel : 0);
            auto& s = *streams.emplace_back(std::make_unique<stream_data>(
                    my_data, rng_seed + i, pregenerate ? my_data : chunk_size, pregenerate ? 1 : chunk_num));

            if (pregenerate)
                gen_data(s.rng, my_data, s.bufs[0]);
        }
        if (pregenerate)
            log::info(SPEEDTEST, "Data pregeneration done");

        auto started_at = std::chrono::steady_clock::now();

        for (size_t i = 0; i < parallel; i++)
        {
            auto& s = *streams[i];
            s.stream = client_ci->open_stream();
            std::string remaining_str;
            remaining_str.resize(8);
            oxenc::write_host_as_little(s.remaining, remaining_str.data());
            s.stream->send(std::move(remaining_str));
            if (pregenerate)
            {
                s.remaining = 0;
                s.done_sending = true;
                s.stream->send(s.bufs[0], nullptr);
            }
            else
            {
                s.stream->send_chunks(
                        [&, i](const Stream&) -> std::vector<std::byte>* {
                            auto& sd = *streams[i];
                            auto& data = sd.bufs[sd.next_buf++];
                            sd.next_buf %= sd.bufs.size();

                            const auto size = std::min(sd.remaining, chunk_size);
                            if (size == 0)
                                return nullptr;

                            gen_data(sd.rng, size, data);

                            sd.remaining -= size;

                            if (sd.remaining == 0)
                                sd.done_sending = true;

                            return &data;
                        },
                        nullptr,
                        chunk_num);
            }
        }

        for (;;)
        {
            bool all_done = true;
            for (auto& s : streams)
            {
                if (!s->done)
                {
                    all_done = false;
                    s->running.get();
                    break;
                }
            }
            if (all_done)
                break;
        }

        bool all_good = true;
        for (auto& s : streams)
        {
            if (s->failed)
            {
                all_good = false;
                break;
            }
        }

        if (!all_good)
            fmt::print("OMG failed!\n");

        auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
        fmt::print("Elapsed time: {:.3f}s\n", elapsed);
        fmt::print("Speed: {:.3f}MB/s\n", size / 1'000'000.0 / elapsed);
    }
    else if (datagram)
    {
        uint64_t max_size =
                std::max<uint64_t>((dgram_size == 0) ? client_ci->get_max_datagram_size() : dgram_size, sizeof(uint8_t));

        dgram_data.emplace(size, max_size);
        log::info(SPEEDTEST, "Preparing to send {} datagrams of max size {}", dgram_data->n_iter, dgram_data->size);

        std::vector<std::byte> remaining_str;
        remaining_str.resize(8);
        oxenc::write_host_as_little(dgram_data->n_iter, remaining_str.data());
        log::info(test_cat, "Sending datagram count to remote...");
        client_ci->datagrams()->send(remaining_str, nullptr);

        std::chrono::steady_clock::time_point started_at;

        dgram_data->is_sending = true;
        log::info(test_cat, "Sending datagrams to remote...");

        started_at = std::chrono::steady_clock::now();

        auto client_dg = client_ci->datagrams();
        for (uint64_t i = 0; i < dgram_data->n_iter - 1; ++i)
        {
            // Just send these with the 0 at the beginning
            client_dg->send(dgram_data->data(i), nullptr);
        }
        // Send a final one always using i = 0 so that we get the bit of the data starting with the
        // terminal 0 byte value.
        client_dg->send(dgram_data->final_data(), nullptr);

        log::info(SPEEDTEST, "All datagrams sent or queued");
        dgram_data->is_sending = false;

        dgram_data->running.get();

        auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
        fmt::print("Elapsed time: {:.5f}s\n", elapsed);
        fmt::print("Speed: {:.5f}MB/s\n", size / 1'000'000.0 / elapsed);
    }
    else
    {
        assert(ping);

        auto startup = std::chrono::steady_clock::now();

        auto stats = run_ping_client(
                client,
                client_tls,
                server_addr,
                ping_count,
                ping_interval,
                ping_timeout,
                !no_ping_log,
                ping_stat_skip,
                ping_reconnect);

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

    return 0;
}

ping_stats run_ping_client(
        const std::shared_ptr<Endpoint>& client,
        const std::shared_ptr<GNUTLSCreds>& creds,
        const RemoteAddress& raddr,
        uint32_t ping_count,
        double ping_interval_d,
        double ping_timeout,
        bool ping_log,
        int stat_skip,
        bool reconn)
{
    ping_stats stats{};

    std::atomic<bool> reconnect{reconn};

    std::optional<std::promise<void>> all_done;
    std::shared_ptr<Ticker> ticker;
    std::chrono::steady_clock::time_point started, established;

#ifndef _WIN32
    auto sig_handler = std::async(std::launch::async, [wclient = std::weak_ptr{client}, &reconnect]() {
        int signum = 0;
        sigwait(&sigs, &signum);
        while (signum != SIGUSR2)  // USR2 is how we gracefully signal this thread on normal exit
        {
            log::warning(SPEEDTEST, "Caught signal, disconnecting");
            reconnect = false;
            if (auto client = wclient.lock())
                client->close_conns();
            sigwait(&sigs, &signum);
        }
        return signum;
    });
#endif

    // Circular buffer so that we can calculate RTTs even if the responses arrive out of order.
    std::array<std::chrono::steady_clock::time_point, 100> sent_at;

    auto dgram_recv = [&](datagram dg) {
        if (dg.data.size() != 4)
        {
            log::error(test_cat, "Invalid ping response datagram; expected 4 bytes, got {}", dg.data.size());
            return;
        }
        auto now = std::chrono::steady_clock::now();

        auto ping_num = oxenc::load_little_to_host<uint32_t>(dg.data.data());
        auto ping_time = now - sent_at[ping_num % sent_at.size()];
        auto rtt = std::chrono::duration<double>{ping_time}.count();
        if (ping_log)
            log::info(SPEEDTEST, "Ping {} received in {}", ping_num, friendly_duration(ping_time));
        stats.received++;
        if (stat_skip > 0)
            --stat_skip;
        else
        {
            stats.rtt_sum += rtt;
            stats.rtt_sumsq += rtt * rtt;
            if (rtt < stats.rtt_min)
                stats.rtt_min = rtt;
            if (rtt > stats.rtt_max)
                stats.rtt_max = rtt;

            if (ping_count && ping_num == ping_count - 1)
                client->close_conns();
        }
    };

    log::info(SPEEDTEST, "Connecting to {}...", raddr);

    std::shared_ptr<Connection> client_conn;
    std::shared_ptr<Datagrams> client_dg;

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
                log::warning(SPEEDTEST, "Timeout waiting for final ping response; disconnecting");
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
            if (!client_dg)
                client_dg = client_conn->datagrams();
            client_dg->send(std::move(counter));
        }
    };

    auto conn_established = [&](Connection& ci) {
        established = get_time();
        log::info(SPEEDTEST, "Connection established to {} in {}", ci.remote(), friendly_duration(established - started));
    };

    auto conn_closed = [&](Connection& ci, uint64_t) {
        log::info(SPEEDTEST, "Disconnected from {}", ci.remote());

        all_done->set_value();
    };

    auto last_start = std::chrono::steady_clock::now() - 2s;
    do
    {
        started = std::chrono::steady_clock::now();
        // Cool down connection attempts to 1/s after a disconnect
        if (started < last_start + 1s)
        {
            std::this_thread::sleep_for(25ms);
            continue;
        }
        last_start = started;
        all_done.emplace();
        client_conn = client->connect(raddr, dgram_recv, creds, conn_established, conn_closed);
        client_dg.reset();

        send_ping();
        if (ticker)
            ticker->stop();
        ticker = client->loop.call_every(ping_wait, send_ping);

        all_done->get_future().wait();
    } while (reconnect);

#ifndef _WIN32
    kill(0, SIGUSR2);  // Wake up the signal handling thread to exit cleanly
#endif

    return stats;
}
