/*
    Test client binary
*/

#include "utils.hpp"

#include <gnutls/crypto.h>

#include <random>
#include <span>
#include <vector>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest client"};

    std::string local_addr, remote_addr = "127.0.0.1:5500"s, remote_pubkey, seed_string;
    bool enable_0rtt;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, enable_0rtt, zerortt_path);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    size_t parallel = 1;
    cli.add_option("-j,--parallel", parallel, "Number of simultaneous streams to send (currently max 32)")
            ->check(CLI::Range(1, 32));

    uint64_t size = 1'000'000'000;
    cli.add_option(
            "-S,--size",
            size,
            "Amount of data to transfer.  When using --parallel the "
            "data is divided equally across streams.");

    bool pregenerate = false;
    cli.add_flag("-g,--pregenerate", pregenerate, "Pregenerate all stream data to send into RAM before starting");

    bool no_hash = false;
    cli.add_flag(
            "-H,--no-hash",
            no_hash,
            "Disable data hashing (just use a simple xor byte checksum instead).  Can make a difference on extremely low "
            "latency (e.g. localhost) connections.  Should be specified on the server as well.");
    bool no_checksum = false;
    cli.add_flag(
            "-X,--no-checksum",
            no_checksum,
            "Disable even the simple xor byte checksum (typically used together with -H).  Should be specified on the "
            "server as well.");

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

        std::vector<std::byte> hash;
        uint8_t checksum = 0;
        gnutls_hash_hd_t sent_hasher, recv_hasher;

        stream_data() {}
        stream_data(size_t total_size, uint64_t seed, size_t chunk_size, size_t chunk_num) : remaining{total_size}, rng{seed}
        {
            bufs.resize(chunk_num);
            for (auto& buf : bufs)
                buf.resize(chunk_size);
            gnutls_hash_init(&sent_hasher, GNUTLS_DIG_SHA3_256);
            gnutls_hash_init(&recv_hasher, GNUTLS_DIG_SHA3_256);
        }

        ~stream_data()
        {
            gnutls_hash_deinit(sent_hasher, nullptr);
            gnutls_hash_deinit(recv_hasher, nullptr);
        }
    };

    setup_logging(log_file, log_level);

    Network client_net{};

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

    stream_data_callback on_stream_data = [&](Stream& s, bspan data) {
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
                    test_cat, "Already got a hash from the other side of stream {}, what is this nonsense‽", s.stream_id());
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
        else if (data.size() != 33)
        {
            log::error(test_cat, "Got unexpected data from the other side: {}B != 32B", data.size());
            sd.failed = true;
        }
        else if (auto first = data.first(32); first != sd.hash)
        {
            log::critical(
                    test_cat,
                    "Hash mismatch: other size said {}, we say {}",
                    oxenc::to_hex(data.begin(), data.end()),
                    oxenc::to_hex(sd.hash.begin(), sd.hash.end()));
            sd.failed = true;
        }
        else if (static_cast<uint8_t>(data[32]) != sd.checksum)
        {
            log::critical(test_cat, "Checksum mismatch: other size said {}, we say {}", data[32], sd.checksum);
            sd.failed = true;
        }
        else
        {
            sd.failed = false;
            log::critical(
                    test_cat,
                    "Hashes matched ({}, {}), hurray!\n",
                    oxenc::to_hex(sd.hash.begin(), sd.hash.end()),
                    sd.checksum);
        }

        sd.done = true;
        sd.run_prom.set_value();
    };

    Address client_local{};
    if (!local_addr.empty())
        client_local = Address::parse(local_addr);

    RemoteAddress server_addr{remote_pubkey, Address::parse(remote_addr, DEFAULT_SPEEDTEST_ADDR.port())};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    auto client = client_net.endpoint(client_local, generate_static_secret(seed_string), opt::alpns{"speedtest"});
    log::debug(test_cat, "Connecting to {}...", server_addr);
    auto client_ci = client->connect(server_addr, client_tls, on_stream_data, stream_closed);

    auto per_stream = size / parallel;

    auto gen_data =
            [no_hash, no_checksum](
                    RNG& rng, size_t size, std::vector<std::byte>& data, gnutls_hash_hd_t& hasher, uint8_t& checksum) {
                assert(size > 0);

                using rng_value = RNG::result_type;

                static_assert(
                        RNG::min() == 0 && std::is_unsigned_v<rng_value> &&
                        RNG::max() == std::numeric_limits<rng_value>::max());

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

                // Hash/checksum it (so that we can verify the hash response at the end)
                if (!no_checksum)
                {
                    uint64_t csum = 0;
                    const uint64_t* stuff = reinterpret_cast<const uint64_t*>(data.data());
                    for (size_t i = 0; i < data.size() / 8; i++)
                        csum ^= stuff[i];
                    for (int i = 0; i < 8; i++)
                        checksum ^= reinterpret_cast<const uint8_t*>(&csum)[i];
                    for (size_t i = data.size() & ~0b111; i < data.size(); i++)
                        checksum ^= static_cast<uint8_t>(data[i]);
                }

                if (!no_hash)
                    gnutls_hash(hasher, reinterpret_cast<unsigned char*>(data.data()), data.size());
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
        {
            gen_data(s.rng, my_data, s.bufs[0], s.sent_hasher, s.checksum);
            s.hash.resize(32);
            gnutls_hash_output(s.sent_hasher, reinterpret_cast<unsigned char*>(s.hash.data()));
        }
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

                        gen_data(sd.rng, size, data, sd.sent_hasher, sd.checksum);

                        sd.remaining -= size;

                        if (sd.remaining == 0)
                        {
                            sd.hash.resize(32);
                            gnutls_hash_output(sd.sent_hasher, reinterpret_cast<unsigned char*>(sd.hash.data()));
                            sd.done_sending = true;
                        }

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
