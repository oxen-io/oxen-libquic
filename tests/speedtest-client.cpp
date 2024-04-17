/*
    Test client binary
*/

#include <oxenc/endian.h>

#include <CLI/Validators.hpp>
#include <chrono>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <random>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test client"};

    std::string remote_addr = "127.0.0.1:5500";
    cli.add_option("--remote", remote_addr, "Remove address to connect to")->type_name("IP:PORT")->capture_default_str();

    std::string remote_pubkey;
    cli.add_option("-p,--remote-pubkey", remote_pubkey, "Remote speedtest-client pubkey")
            ->type_name("PUBKEY_HEX_OR_B64")
            ->transform([](const std::string& val) -> std::string {
                if (auto pk = decode_bytes(val))
                    return std::move(*pk);
                throw CLI::ValidationError{
                        "Invalid value passed to --remote-pubkey: expected value encoded as hex or base64"};
            })
            ->required();

    std::string local_addr = "";
    cli.add_option("--local", local_addr, "Local bind address, if required")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    size_t parallel = 1;
    cli.add_option("-j,--parallel", parallel, "Number of simultaneous streams to send (currently max 32)")
            ->check(CLI::Range(1, 32));

    bool receive = false;
    cli.add_option(
            "-R,--receive",
            receive,
            "If specified receive data from the server instead than sending data.  Ignored if --bidir is specified.");

    bool bidir = false;
    cli.add_option("-B,--bidir", bidir, "Test transfer *and* receiving; if omitted only send or receive (see --receive)");

    uint64_t size = 1'000'000'000;
    cli.add_option(
            "-S,--size",
            size,
            "Amount of data to transfer (if using --bidir, this amount is in each direction).  When using --parallel the "
            "data is divided equally across streams.");

    bool pregenerate = false;
    cli.add_flag("-g,--pregenerate", pregenerate, "Pregenerate all stream data to send into RAM before starting");

    size_t chunk_size = 64_ki, chunk_num = 2;
    cli.add_option("--stream-chunk-size", chunk_size, "How much data to queue at once, per chunk");
    cli.add_option("--stream-chunks", chunk_num, "How much chunks to queue at once per stream")->check(CLI::Range(1, 100));

    size_t rng_seed = 0;
    cli.add_option(
            "--rng-seed",
            rng_seed,
            "RNG seed to use for data generation; with --parallel we use this, this+1, ... for the different threads.");

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    using RNG = std::mt19937_64;

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

    setup_logging(log_file, log_level);

    Network client_net{};

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    std::vector<std::unique_ptr<stream_data>> streams;
    streams.reserve(parallel);

    stream_close_callback stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id() >> 2;
        log::critical(test_cat, "Stream {} (rawid={}) closed (error={})", i, s.stream_id(), errcode);
    };

    stream_data_callback on_stream_data = [&](Stream& s, bstring_view data) {
        size_t i = s.stream_id() >> 2;
        if (i >= parallel)
        {
            log::critical(test_cat, "Something getting wrong: got unexpected stream id {}", s.stream_id());
            return;
        }

        auto& sd = *streams[i];
        if (sd.done)
        {
            log::error(
                    test_cat,
                    "Already got a DONE! reply from the other side of stream {}, what is this nonsense‽",
                    s.stream_id());
            return;
        }

        if (!sd.done_sending)
        {
            log::error(
                    test_cat,
                    "Got a stream (stream {}) response ({}B) before we were done sending data!",
                    s.stream_id(),
                    data.size());
            sd.failed = true;
        }
        else if (data != "DONE!"_bsv)
        {
            log::error(test_cat, "Got unexpected data from the other side: (hex) {}", oxenc::to_hex(data));
            sd.failed = true;
        }

        sd.done = true;
        sd.run_prom.set_value();
    };

    Address client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = Address{a, p};
    }

    auto [server_a, server_p] = parse_addr(remote_addr);
    RemoteAddress server_addr{remote_pubkey, server_a, server_p};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    auto client = client_net.endpoint(client_local);
    log::debug(test_cat, "Connecting to {}...", server_addr);
    auto client_ci = client->connect(server_addr, client_tls, on_stream_data, stream_closed);

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

    if (pregenerate)
    {
        log::warning(test_cat, "Pregenerating data...");
    }

    for (size_t i = 0; i < parallel; i++)
    {
        uint64_t my_data = per_stream + (i == 0 ? size % parallel : 0);
        auto& s = *streams.emplace_back(std::make_unique<stream_data>(
                my_data, rng_seed + i, pregenerate ? my_data : chunk_size, pregenerate ? 1 : chunk_num));

        if (pregenerate)
            gen_data(s.rng, my_data, s.bufs[0]);
    }
    if (pregenerate)
    {
        log::warning(test_cat, "Data pregeneration done");
    }

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
            s.stream->send(bstring_view{s.bufs[0].data(), s.bufs[0].size()});
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

    return 0;
}
