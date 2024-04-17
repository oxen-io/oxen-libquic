#include "utils.hpp"

#include <nettle/eddsa.h>

namespace oxen::quic
{
    void TestHelper::migrate_connection(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        auto rv = ngtcp2_conn_initiate_migration(conn, conn._path, get_timestamp().count());
        log::trace(log_cat, "{}", ngtcp2_strerror(rv));
    }

    void TestHelper::migrate_connection_immediate(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        auto rv = ngtcp2_conn_initiate_immediate_migration(conn, conn._path, get_timestamp().count());
        log::trace(log_cat, "{}", ngtcp2_strerror(rv));
    }

    void TestHelper::nat_rebinding(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        ngtcp2_conn_set_local_addr(conn, &new_addr._addr);
    }

    Connection* TestHelper::get_conn(std::shared_ptr<Endpoint>& ep, std::shared_ptr<connection_interface>& _conn)
    {
        auto* conn = static_cast<Connection*>(_conn.get());
        return ep->get_conn(conn->_source_cid);
    }

    void TestHelper::enable_dgram_drop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_flip_flop_enabled = false;
            conn.debug_datagram_drop_enabled = true;
            conn.debug_datagram_counter = 0;
        });
    }
    int TestHelper::disable_dgram_drop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] {
            conn.debug_datagram_drop_enabled = false;
            int count = 0;
            std::swap(count, conn.debug_datagram_counter);
            return count;
        });
    }
    void TestHelper::enable_dgram_flip_flop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_drop_enabled = false;
            conn.debug_datagram_flip_flop_enabled = true;
            conn.debug_datagram_counter = 0;
        });
    }
    int TestHelper::disable_dgram_flip_flop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] {
            conn.debug_datagram_flip_flop_enabled = false;
            int count = 0;
            std::swap(count, conn.debug_datagram_counter);
            return count;
        });
    }
    int TestHelper::get_dgram_debug_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] { return conn.debug_datagram_counter; });
    }

    void TestHelper::increment_ref_id(Endpoint& ep, uint64_t by)
    {
        ep._next_rid += by;
    }

    std::pair<std::shared_ptr<GNUTLSCreds>, std::shared_ptr<GNUTLSCreds>> test::defaults::tls_creds_from_ed_keys()
    {
        auto client = GNUTLSCreds::make_from_ed_keys(CLIENT_SEED, CLIENT_PUBKEY);
        auto server = GNUTLSCreds::make_from_ed_keys(SERVER_SEED, SERVER_PUBKEY);

        return std::make_pair(std::move(client), std::move(server));
    }

    std::string make_keypair(std::string& seed)
    {
        std::string pubkey;
        if (seed.empty())
        {
            seed.resize(32);
            gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, seed.data(), sizeof(seed.size()));
        }
        else if (auto decoded = decode_bytes(seed, 32))
        {
            seed = std::move(*decoded);
        }
        else
        {
            log::critical(test_cat, "Invalid --seed value: expected 64 hex characters");
            throw std::logic_error{"Invalid --seed value"};
        }

        pubkey.resize(32);
        ed25519_sha512_public_key(
                reinterpret_cast<unsigned char*>(pubkey.data()), reinterpret_cast<const unsigned char*>(seed.data()));
        return pubkey;
    }

    std::pair<std::string, std::string> generate_ed25519()
    {
        std::pair<std::string, std::string> ret;
        ret.second = make_keypair(ret.first);
        return ret;
    }

    void add_log_opts(CLI::App& cli, std::string& file, std::string& level)
    {
        file = "stderr";
        level = "info";

        cli.add_option("-l,--log-file", file, "Log output filename, or one of stdout/-/stderr/syslog.")
                ->type_name("FILE")
                ->capture_default_str();

        cli.add_option("-L,--log-level", level, "Log verbosity level; one of trace, debug, info, warn, error, critical, off")
                ->type_name("LEVEL")
                ->capture_default_str()
                ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "critical", "off"}));
    }

    void add_seed_opt(CLI::App& cli, std::string& seed)
    {
        cli.add_option(
                   "--seed",
                   seed,
                   "Provide a server Ed25519 seed value, in hex (64 characters) instead of generating a random one.")
                ->type_name("HEX");
    }

    void setup_logging(std::string out, const std::string& level)
    {
        log::Level lvl = log::level_from_string(level);

        constexpr std::array print_vals = {"stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
        log::Type type;
        if (std::count(print_vals.begin(), print_vals.end(), out))
            type = log::Type::Print;
        else if (out == "syslog")
            type = log::Type::System;
        else
            type = log::Type::File;

        logger_config(out, type, lvl);
    }

}  // namespace oxen::quic
