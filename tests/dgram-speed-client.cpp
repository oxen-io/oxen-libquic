/*
    Test client binary
*/

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <chrono>
#include <future>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <random>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test client"};

    std::string remote_addr = "127.0.0.1:5500";
    cli.add_option("--remote", remote_addr, "Remove address to connect to")->type_name("IP:PORT")->capture_default_str();

    std::string local_addr = "";
    cli.add_option("--local", local_addr, "Local bind address, if required")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_cert{"./servercert.pem"};
    cli.add_option("-c,--servercert", server_cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    uint64_t size = 1'000'000'000;
    cli.add_option("-S,--size", size, "Amount of data to transfer.");

    bool pregenerate = true;
    cli.add_flag("-g,--pregenerate", pregenerate, "Pregenerate all stream data to send into RAM before starting");

    size_t dgram_size = 0;
    cli.add_option("--dgram-size", dgram_size, "Datagram size to send");

    // TODO: make this optional
    std::string cert{"./clientcert.pem"}, key{"./clientkey.pem"};
    cli.add_option("-C,--certificate", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-K,--key", key, "Path to client key to use for client authentication")
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

    struct send_data
    {
        std::shared_ptr<Stream> stream;
        std::atomic<bool> active = false;
        std::basic_string<uint8_t> msg{};
        uint64_t size;
        uint64_t dgram_size;
        uint64_t n_iter;
        std::atomic<bool> is_sending = false;
        std::atomic<bool> is_done = false;
        std::promise<void> run_prom;
        std::future<void> running = run_prom.get_future();
        std::atomic<bool> failed = false;

        send_data() {}
        send_data(uint64_t _total_size, uint64_t _dgram_size) : size{_total_size}, dgram_size{_dgram_size}
        {
            n_iter = size / dgram_size + 1;

            log::warning(test_cat, "Preparing to send {} datagrams of max size {}", n_iter, size);

            uint8_t v{0};

            while (msg.size() < dgram_size)
                msg += v++;
        }
    };

    setup_logging(log_file, log_level);

#ifdef ENABLE_PERF_TESTING
    Network client_net{};

    auto client_tls = GNUTLSCreds::make(key, cert, server_cert);

    send_data* d_ptr;

    stream_close_callback stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id() >> 2;
        log::critical(test_cat, "Stream {} (rawid={}) closed (error={})", i, s.stream_id(), errcode);
    };

    dgram_data_callback recv_dgram_cb = [&](dgram_interface, bstring data) {
        log::critical(test_cat, "Calling endpoint receive datagram callback... data received...");

        if (d_ptr->is_sending)
        {
            log::error(test_cat, "Got a datagram response ({}B) before we were done sending data!", data.size());
            d_ptr->failed = true;
        }
        else if (data.size() != 5)
        {
            log::error(test_cat, "Got unexpected data from the other side: {}B != 5B", data.size());
            d_ptr->failed = true;
        }
        else if (data != "DONE!"_bsv)
        {
            log::error(
                    test_cat,
                    "Got unexpected data: expected 'DONE!', got (hex): '{}'",
                    oxenc::to_hex(data.begin(), data.end()));
            d_ptr->failed = true;
        }
        else
        {
            d_ptr->failed = false;
            log::critical(test_cat, "All done, hurray!\n");
        }

        d_ptr->is_done = true;
        d_ptr->run_prom.set_value();
    };

    opt::local_addr client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = opt::local_addr{a, p};
    }

    std::promise<bool> tls;
    std::future<bool> tls_future = tls.get_future();

    gnutls_callback outbound_tls_cb =
            [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                log::debug(test_cat, "Calling client TLS callback... handshake completed...");

                tls.set_value(true);
                return 0;
            };

    auto [server_a, server_p] = parse_addr(remote_addr);
    opt::remote_addr server_addr{server_a, server_p};
    auto split_dgram = opt::enable_datagrams(Splitting::ACTIVE);
    // opt::enable_datagrams split_dgram(Splitting::ACTIVE);

    client_tls->set_client_tls_policy(outbound_tls_cb);

    log::critical(test_cat, "Calling 'client_connect'...");
    auto client = client_net.endpoint(client_local, recv_dgram_cb, split_dgram);
    auto client_ci = client->connect(server_addr, client_tls, stream_closed);

    tls_future.get();

    uint64_t max_size = (dgram_size == 0) ? client_ci->get_max_datagram_size() : dgram_size;

    send_data dgram_data{size, max_size};
    d_ptr = &dgram_data;

    bstring remaining_str;
    remaining_str.resize(8);
    oxenc::write_host_as_little(d_ptr->n_iter, remaining_str.data());
    log::warning(test_cat, "Sending datagram count to remote...");
    client_ci->send_datagram(bstring_view{remaining_str.data(), remaining_str.size()});

    std::promise<void> send_prom;
    std::future<void> send_f = send_prom.get_future();

    std::chrono::steady_clock::time_point started_at;

    client->call([&]() {
        d_ptr->is_sending = true;
        log::warning(test_cat, "Sending payload to remote...");

        started_at = std::chrono::steady_clock::now();

        for (uint64_t i = 0; i < d_ptr->n_iter; ++i)
            client_ci->send_datagram(std::basic_string_view<uint8_t>{d_ptr->msg.data(), d_ptr->msg.size()});

        log::warning(test_cat, "Client done sending payload to remote!");
        d_ptr->is_sending = false;

        send_prom.set_value();
    });

    send_f.get();
    d_ptr->running.get();

    auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
    fmt::print("Elapsed time: {:.5f}s\n", elapsed);
    fmt::print("Speed: {:.5f}MB/s\n", size / 1'000'000.0 / elapsed);

    client_net.close();

    return 0;
#else
    log::error(log_cat, "Error: library must be compiled with cmake flag -DENABLE_PERF_TESTING=1 to enable test binaries");
#endif
}
