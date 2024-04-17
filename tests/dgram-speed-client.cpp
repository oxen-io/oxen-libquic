/*
    Test client binary
*/

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <chrono>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <random>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

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

    uint64_t size = 1'000'000'000;
    cli.add_option("-S,--size", size, "Amount of data to transfer.");

    size_t dgram_size = 0;
    cli.add_option("--dgram-size", dgram_size, "Datagram size to send");

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
        ustring msg{};
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

            msg.resize(dgram_size);
            // Byte 0 must be set to 0, except for the final packet where we set it to 1
            for (uint64_t i = 0; i < dgram_size; i++)
                msg[i] = static_cast<unsigned char>(i % 256);
        }
    };

    setup_logging(log_file, log_level);

    Network client_net{};

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

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
        else if (uint64_t server_got;
                 data.starts_with("DONE-"_bsv) && parse_int(to_sv(bstring_view{data}).substr(5), server_got))
        {
            log::critical(
                    test_cat,
                    "All done, hurray!  Server fidelity: {}\% ({} received of {} sent)",
                    server_got / (float)d_ptr->n_iter * 100,
                    server_got,
                    d_ptr->n_iter);
            d_ptr->failed = false;
        }
        else
        {
            log::error(
                    test_cat,
                    "Got unexpected data from the other side: expected 'DONE-(count)', got (hex): '{}'",
                    oxenc::to_hex(data.begin(), data.end()));
            d_ptr->failed = true;
        }

        d_ptr->is_done = true;
        d_ptr->run_prom.set_value();
    };

    Address client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = Address{a, p};
    }

    std::promise<bool> tls;
    std::future<bool> tls_future = tls.get_future();

    auto client_established = callback_waiter{[](connection_interface&) {}};

    auto [server_a, server_p] = parse_addr(remote_addr);
    RemoteAddress server_addr{remote_pubkey, server_a, server_p};
    opt::enable_datagrams split_dgram(Splitting::ACTIVE);

    log::critical(test_cat, "Calling 'client_connect'...");
    auto client = client_net.endpoint(client_local, client_established, recv_dgram_cb, split_dgram);
    auto client_ci = client->connect(server_addr, client_tls, stream_closed);

    client_established.wait();

    uint64_t max_size =
            std::max<uint64_t>((dgram_size == 0) ? client_ci->get_max_datagram_size() : dgram_size, sizeof(uint8_t));

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

        for (uint64_t i = 1; i < d_ptr->n_iter; ++i)
        {
            // Just send these with the 0 at the beginning
            client_ci->send_datagram(ustring_view{d_ptr->msg});
        }
        // Send a final one with the max value in the beginning so the server knows its done
        ustring last_payload{d_ptr->msg};
        last_payload[0] = 1;  // Signals that this is the last one
        client_ci->send_datagram(std::move(last_payload));

        log::warning(test_cat, "Client done sending payload to remote!");
        d_ptr->is_sending = false;

        send_prom.set_value();
    });

    send_f.get();
    d_ptr->running.get();

    auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
    fmt::print("Elapsed time: {:.5f}s\n", elapsed);
    fmt::print("Speed: {:.5f}MB/s\n", size / 1'000'000.0 / elapsed);

    return 0;
}
