#include "utils.hpp"

#include <oxen/quic/opt.hpp>

#include <nettle/eddsa.h>
#include <nettle/sha3.h>

#include <chrono>
#include <fstream>

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
        log::trace(test_cat, "{}", ngtcp2_strerror(rv));
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
        log::trace(test_cat, "{}", ngtcp2_strerror(rv));
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

    UDPSocket::socket_t TestHelper::get_sock(Endpoint& ep)
    {
        return ep.get_socket()->sock_;
    }

    void TestHelper::enable_dgram_drop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_counter_enabled = false;
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
    void TestHelper::enable_dgram_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_drop_enabled = false;
            conn.debug_datagram_counter_enabled = true;
            conn.debug_datagram_counter = 0;
        });
    }
    int TestHelper::disable_dgram_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] {
            conn.debug_datagram_counter_enabled = false;
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

    void sha3_256(uint8_t* out, std::span<const uint8_t> value, std::string_view domain)
    {
        sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        if (!domain.empty())
            sha3_256_update(&ctx, domain.size(), reinterpret_cast<const uint8_t*>(domain.data()));

        sha3_256_update(&ctx, value.size(), value.data());
        sha3_256_digest(&ctx, 32, out);
    }
    void sha3_256(uint8_t* out, std::span<const char> value, std::string_view domain)
    {
        return sha3_256(out, {reinterpret_cast<const uint8_t*>(value.data()), value.size()}, domain);
    }
    void sha3_512(uint8_t* out, std::span<const uint8_t> value, std::string_view domain)
    {
        sha3_512_ctx ctx;
        sha3_512_init(&ctx);
        if (!domain.empty())
            sha3_512_update(&ctx, domain.size(), reinterpret_cast<const uint8_t*>(domain.data()));

        sha3_512_update(&ctx, value.size(), value.data());
        sha3_512_digest(&ctx, 32, out);
    }
    void sha3_512(uint8_t* out, std::span<const char> value, std::string_view domain)
    {
        return sha3_512(out, {reinterpret_cast<const uint8_t*>(value.data()), value.size()}, domain);
    }

    std::pair<std::string, std::string> generate_ed25519(std::string_view seed_string)
    {

        std::pair<std::string, std::string> result;
        auto& [seed, pubkey] = result;
        seed.resize(32);

        if (!seed_string.empty())
        {
            log::info(test_cat, "Generating insecure but reproducible keys from seed string '{}'", seed_string);
            sha3_256(reinterpret_cast<uint8_t*>(seed.data()), seed_string, "libquic-test-ed25519-generator");
        }
        else
        {
            gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, seed.data(), seed.size());
        }

        pubkey.resize(32);
        ed25519_sha512_public_key(
                reinterpret_cast<unsigned char*>(pubkey.data()), reinterpret_cast<const unsigned char*>(seed.data()));

        return result;
    }

    opt::static_secret generate_static_secret(std::string_view seed_string)
    {
        std::vector<unsigned char> ep_secret;
        ep_secret.resize(32);
        if (seed_string.empty())
            gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, ep_secret.data(), ep_secret.size());
        else
            sha3_256(ep_secret.data(), seed_string, "libquic-test-static-secret");
        return opt::static_secret{std::move(ep_secret)};
    }

    std::optional<std::string> decode_bytes(std::string_view encoded, size_t size)
    {
        if (encoded.size() == size * 2 && oxenc::is_hex(encoded))
            return oxenc::from_hex(encoded);
        if (encoded.size() >= oxenc::to_base64_size(size, false) && encoded.size() <= oxenc::to_base64_size(32, true) &&
            oxenc::is_base64(encoded))
            return oxenc::from_base64(encoded);
        return std::nullopt;
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

    void common_server_opts(CLI::App& cli, std::string& server_listen, std::string& seed_string, bool& enable_0rtt)
    {
        seed_string.clear();
        enable_0rtt = false;

        cli.add_option("--listen", server_listen, "Server address to listen on")
                ->type_name("IP:PORT")
                ->capture_default_str();

        cli.add_option(
                "-s,--seed",
                seed_string,
                "If non-empty then the server key and endpoint private data will be generated from a hash of the given "
                "seed, "
                "for reproducible keys and operation.  If omitted/empty a random seed is used.");

        cli.add_flag("-Z,--enable-0rtt", enable_0rtt, "Enable 0-RTT early data for this endpoint");
    }

    void common_client_opts(
            CLI::App& cli,
            std::string& local_addr,
            std::string& remote_addr,
            std::string& remote_pubkey,
            std::string& seed_string,
            bool& enable_0rtt,
            std::filesystem::path& store_0rtt)
    {
        if (remote_addr.empty())
            remote_addr = "127.0.0.1:5500";
        remote_pubkey.clear();
        seed_string.clear();
        enable_0rtt = false;
        if (store_0rtt.empty())
            store_0rtt = std::filesystem::path{u8"./libquic-test-0rtt-cache.bin"};

        cli.add_option("-R,--remote", remote_addr, "Remote address to connect to")
                ->type_name("IP:PORT")
                ->capture_default_str();

        auto* rem_pubkey = cli.add_option_group("remote pubkey");
        rem_pubkey->add_option("-P,--remote-pubkey", remote_pubkey, "Remote server pubkey")
                ->type_name("HEX_OR_B64")
                ->transform([](const std::string& val) -> std::string {
                    if (auto pk = decode_bytes(val))
                        return std::move(*pk);
                    throw CLI::ValidationError{
                            "Invalid value passed to --remote-pubkey: expected value encoded as hex or base64"};
                });
        rem_pubkey->add_option("--remote-seed", remote_pubkey, "Calculate server pubkey using this server seed value")
                ->transform([](const std::string& val) { return generate_ed25519(val).second; });
        rem_pubkey->require_option(1);

        cli.add_flag("-Z,--enable-0rtt", enable_0rtt, "Enable 0-RTT early data for this endpoint");
        cli.add_option("-z,--zerortt-storage", store_0rtt, "Path to load and store 0rtt information from.");

        cli.add_option("--local", local_addr, "Local bind address (optional)")->type_name("IP:PORT")->capture_default_str();

        cli.add_option(
                "-s,--seed",
                seed_string,
                "If non-empty then the client key and endpoint private data will be generated from a hash of the given "
                "seed, for reproducible keys and operation.  If omitted/empty a random seed is used.");
    }

    void server_log_listening(
            const Address& server_local,
            const Address& default_local,
            const std::string& pubkey,
            const std::string& seed_string,
            bool enable_0rtt,
            std::string_view extra)
    {
        // We always want to see this log statement because it contains the pubkey the client needs,
        // but it feels wrong to force it to a critical statement, so temporarily lower the level to
        // info to display it.
        log_level_lowerer enable_info{log::Level::info, test_cat.name};
        std::vector<std::vector<std::string>> flags;
        flags.resize(seed_string.empty() ? 1 : 2);
        flags[0].push_back("-P {}"_format(oxenc::to_base64(pubkey)));
        if (!seed_string.empty())
        {
            auto quote = seed_string.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") !=
                                         std::string::npos
                               ? "'"sv
                               : ""sv;
            flags[1].push_back("--remote-seed {0}{1}{0}"_format(quote, seed_string));
        }

        for (auto& f : flags)
        {
            if (server_local != default_local)
                f.push_back("-R {}"_format(server_local.to_string()));
            if (enable_0rtt)
                f.emplace_back("-Z");
            if (!extra.empty())
                f.emplace_back(extra);
        }

        std::string flags_out;
        flags_out += "        {}"_format(fmt::join(flags[0], " "));
        for (size_t i = 1; i < flags.size(); i++)
            flags_out += "\n    or:\n        {}"_format(fmt::join(flags[i], " "));

        log::info(test_cat, "Listening on {}; client connection args:\n{}", server_local, flags_out);
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

        oxen::log::add_sink(type, out, "[%T.%f] [%*] [\x1b[1m%n\x1b[0m:%^%l%$|\x1b[3m%g:%#\x1b[0m] %v");
        oxen::log::reset_level(lvl);

        if (lvl <= oxen::log::Level::trace)
            enable_gnutls_logging();
    }

    zerortt_storage::zerortt_storage(std::filesystem::path p) : path{std::move(p)}
    {
        load();
    }
    void zerortt_storage::load(bool prune_expired)
    {
        if (std::filesystem::exists(path))
        {
            std::ifstream in;
            in.exceptions(std::ios::failbit);
            in.open(path, std::ios::binary);
            in.seekg(0, std::ios::end);
            std::string dumped;
            dumped.resize(in.tellg());
            in.seekg(0, std::ios::beg);
            in.read(dumped.data(), dumped.size());

            oxenc::bt_deserialize(dumped, data);

            if (prune_expired)
                clear_expired();
        }
        else
            data.clear();
    }

    bool zerortt_storage::clear_expired()
    {
        bool modified = false;
        for (auto it = data.begin(); it != data.end();)
        {
            auto& [pk, tickets] = *it;
            for (auto it = tickets.begin(); it != tickets.end();)
            {
                auto& exp = it->second;
                if (std::chrono::system_clock::from_time_t(exp) < std::chrono::system_clock::now())
                {
                    log::trace(log_cat, "Dropping expired 0-RTT session data for pubkey {}", oxenc::to_hex(pk));
                    it = tickets.erase(it);
                    modified = true;
                }
                else
                    ++it;
            }
            if (tickets.empty())
            {
                modified = true;
                it = data.erase(it);
            }
            else
                ++it;
        }
        return modified;
    }

    void zerortt_storage::dump(bool prune_expired)
    {
        if (prune_expired)
            clear_expired();

        std::ofstream out;
        out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        out.open(path, std::ios::binary | std::ios::out | std::ios::trunc);
        auto contents = oxenc::bt_serialize(data);
        out.write(contents.data(), contents.size());
    }

    void zerortt_storage::store(
            const RemoteAddress& remote,
            std::vector<unsigned char> vdata,
            std::chrono::system_clock::time_point expiry,
            bool dump_now)
    {
        log::debug(log_cat, "Storing 0-RTT session data for remote {}", remote);

        auto ukey = remote.view_remote_key();
        std::string key{reinterpret_cast<const char*>(ukey.data()), ukey.size()};
        std::string session_data{reinterpret_cast<const char*>(vdata.data()), vdata.size()};
        data[key].emplace_back(std::move(session_data), std::chrono::system_clock::to_time_t(expiry));
        if (dump_now)
            dump();
    }
    std::optional<std::vector<unsigned char>> zerortt_storage::extract(const RemoteAddress& remote, bool dump_now)
    {
        log::debug(log_cat, "Looking up 0-RTT session data for remote {}", remote);
        bool modified = clear_expired();
        auto ukey = remote.view_remote_key();
        std::string key{reinterpret_cast<const char*>(ukey.data()), ukey.size()};
        std::optional<std::vector<unsigned char>> result;
        auto it = data.find(key);
        if (it != data.end())
        {
            auto& mine = it->second;
            auto now = std::chrono::system_clock::now();
            result.emplace(mine.back().first.size());
            std::memcpy(result->data(), mine.back().first.data(), result->size());
            log::debug(
                    log_cat,
                    "Found 0-RTT session data with expiry +{}s; {} session data remaining",
                    std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::from_time_t(mine.back().second) - now)
                            .count(),
                    mine.size() - 1);
            mine.pop_back();
            if (mine.empty())
                data.erase(it);
            modified = true;
        }
        else
            log::debug(log_cat, "No 0-RTT session data found");

        if (modified && dump_now)
            dump();

        return result;
    }

    void zerortt_storage::enable(GNUTLSCreds& creds, std::filesystem::path path)
    {
        auto zstore = std::make_shared<zerortt_storage>(std::move(path));
        creds.enable_outbound_0rtt(
                [zstore](
                        const RemoteAddress& remote,
                        std::vector<unsigned char> vdata,
                        std::chrono::system_clock::time_point expiry) { zstore->store(remote, vdata, expiry); },
                [zstore](const RemoteAddress& remote) { return zstore->extract(remote); });
    }

    std::string friendly_duration(std::chrono::nanoseconds dur)
    {
        std::string friendly;
        auto append = std::back_inserter(friendly);
        bool some = false;
        if (dur >= 24h)
        {
            fmt::format_to(append, "{}d", dur / 24h);
            dur %= 24h;
            some = true;
        }
        if (dur >= 1h || some)
        {
            fmt::format_to(append, "{}h", dur / 1h);
            dur %= 1h;
            some = true;
        }
        if (dur >= 1min || some)
        {
            fmt::format_to(append, "{}m", dur / 1min);
            dur %= 1min;
            some = true;
        }
        if (some || dur % 1s == 0ns)
        {
            // If we have >= minutes or its an integer number of seconds then don't bother with
            // fractional seconds
            fmt::format_to(append, "{}s", dur / 1s);
        }
        else
        {
            double seconds = std::chrono::duration<double>(dur).count();
            if (dur >= 1s)
                fmt::format_to(append, "{:.3f}s", seconds);
            else if (dur >= 1ms)
                fmt::format_to(append, "{:.3f}ms", seconds * 1000);
            else if (dur >= 1us)
                fmt::format_to(append, "{:.3f}µs", seconds * 1'000'000);
            else
                fmt::format_to(append, "{:.0f}ns", seconds * 1'000'000'000);
        }
        return friendly;
    }

    std::shared_ptr<packet_delayer> packet_delayer::make(std::chrono::milliseconds delay)
    {
        return std::shared_ptr<packet_delayer>{new packet_delayer{delay}};
    }

    void packet_delayer::init(std::shared_ptr<Loop> loop_, std::shared_ptr<Endpoint> ep_)
    {
        if (ep)
            throw std::logic_error{"Cannot call packet_delayer::init more than once"};
        ep = std::move(ep_);
        loop = std::move(loop_);
        if (!ep || !loop)
            throw std::logic_error{"packet_delayer::init called with nullptr endpoint and/or loop"};

        sock = std::make_unique<UDPSocket>(loop->loop().get(), ep->local(), [wself = weak_from_this()](Packet&& pkt) {
            log::debug(log_cat, "incoming {}B udp packet from {}; delaying delivery", pkt.size(), pkt.path);
            auto self = wself.lock();
            if (!self)
                return;

            pkt.ensure_owned_data();
            self->loop->call_later(self->delay.load(), [wself, pkt = std::move(pkt)]() mutable {
                log::debug(log_cat, "completing incoming delayed delivery of {}B packet on path {}", pkt.size(), pkt.path);
                if (auto self = wself.lock())
                    self->ep->manually_receive_packet(std::move(pkt));
            });
        });
        ep->set_local(sock->address());
    }

    packet_delayer::operator opt::manual_routing()
    {
        return opt::manual_routing{[wself = weak_from_this()](const Path& p, std::span<const std::byte> pkt) {
            log::debug(log_cat, "outgoing {}B packet along {}; delaying delivery", pkt.size(), p);
            auto self = wself.lock();
            if (!self)
                return;
            if (!self->loop || !self->ep)
            {
                log::critical(log_cat, "Error: packet_delayer received packet without a call to init()");
                return;
            }
            self->loop->call_later(self->delay.load(), [wself, path = p, data = std::vector(pkt.begin(), pkt.end())] {
                log::debug(log_cat, "completing outgoing delayed delivery of {}B packet along {}", data.size(), path);
                if (auto self = wself.lock())
                {
                    size_t sz = data.size();
                    auto [res, sent] = self->sock->send(path, data.data(), &sz, 0, 1);
                    if (sent != 1)
                        log::critical(
                                log_cat,
                                "Error: packet_delayer failed to send, and no retry queue is implemented; dropping packet");
                }
                else
                {
                }
            });
        }};
    }

}  // namespace oxen::quic
