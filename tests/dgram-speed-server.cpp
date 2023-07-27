/*
    Test server binary
*/

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "quic/connection.hpp"
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

    // optional
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

    datagram_test_enabled = true;

    Network server_net{};

    auto server_tls = GNUTLSCreds::make(key, cert, client_cert);

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    opt::local_addr server_local{listen_addr, listen_port};

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct recv_info
    {
        explicit recv_info() { gnutls_hash_init(&hasher, GNUTLS_DIG_SHA3_256); }
        explicit recv_info(uint64_t expected) : n_expected{expected} { gnutls_hash_init(&hasher, GNUTLS_DIG_SHA3_256); }

        uint64_t n_expected = 0;
        uint64_t n_received = 0;
        unsigned char checksum = 0;
        gnutls_hash_hd_t hasher;

        ~recv_info() { gnutls_hash_deinit(hasher, nullptr); }
    };

    recv_info dgram_data;
    auto _overflow = 65534;
    auto overflow = 16383;
    std::atomic<uint64_t> carry = 0;

    std::promise<void> t_prom;
    std::future<void> t_fut = t_prom.get_future();

    std::shared_ptr<connection_interface> server_ci;
    std::shared_ptr<Endpoint> server;

    gnutls_callback outbound_tls_cb =
            [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                log::debug(test_cat, "Calling server TLS callback... handshake completed...");

                server_ci = server->get_all_conns(Direction::INBOUND).front();
                return 0;
            };

    server_tls->set_server_tls_policy(outbound_tls_cb);

    dgram_data_callback recv_dgram_cb = [&](bstring data) {
        if (dgram_data.n_expected == 0)
        {
            data = data.substr(2);
            auto count = oxenc::load_little_to_host<uint64_t>(data.data());
            data = data.substr(sizeof(uint64_t));
            dgram_data.n_expected = count + 1;
            dgram_data.n_received += 1;
            log::warning(
                    test_cat,
                    "First data from new connection datagram channel, expecting {} datagrams!",
                    dgram_data.n_expected);
            return;
        }

        uint16_t raw = oxenc::load_big_to_host<uint16_t>(bstring_view{data.data(), size_t(2)}.data());
        uint16_t _dgid = (raw >> 2);
        uint64_t dgid = _dgid + (overflow * carry) + carry;

        log::debug(test_cat, "Received datagram number: raw: {}, dgid: {}, carry: {}", raw, dgid, carry);

        if (raw % _overflow == 0)
            carry += 1;

        auto& info = dgram_data;
        bool need_more = info.n_received < info.n_expected;
        info.n_received += 1;

        if (info.n_received > info.n_expected)
        {
            log::critical(test_cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);

            if (!need_more)
                return;
        }

        log::debug(test_cat, "Received {} of {} datagrams expected", info.n_received, info.n_expected);

        if (dgid >= info.n_expected)
        {
            log::critical(test_cat, "Received datagram ID:{} of {} datagrams expected", dgid, info.n_expected);

            bstring final_hash;
            final_hash.resize(33);
            gnutls_hash_output(info.hasher, final_hash.data());
            final_hash[32] = *reinterpret_cast<std::byte*>(&info.checksum);

            auto reception_rate = ((float)info.n_received / (float)info.n_expected) * 100;

            log::critical(
                    test_cat,
                    "Datagram test complete. Fidelity: {}\% ({} received of {} expected)",
                    reception_rate,
                    info.n_received,
                    info.n_expected);

            server_ci->send_datagram(final_hash);
            t_prom.set_value();
        }
    };

    log::critical(test_cat, "Calling 'server_listen'...");
    opt::enable_datagrams split_dgram{Splitting::ACTIVE};
    server = server_net.endpoint(server_local, recv_dgram_cb, split_dgram);
    server->listen(server_tls, stream_opened);

    t_fut.get();

    log::warning(test_cat, "Shutting down test server");
    server_net.close();
}
