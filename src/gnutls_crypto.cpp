#include "gnutls_crypto.hpp"

#include "address.hpp"
#include "connection.hpp"
#include "connection_ids.hpp"
#include "crypto.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"

#include <oxen/log/level.hpp>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <fmt/core.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <nettle/sha3.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace oxen::quic
{
#ifdef NDEBUG
    void enable_gnutls_logging(int) {}
#else
    extern "C" void gnutls_log(int level, const char* str)
    {
        static auto cat = log::Cat("gnutls");
        std::string_view msg{str};
        if (msg.ends_with('\n'))
            msg.remove_suffix(1);
        cat->log(spdlog::source_loc{"LEVEL", level, "gnutls"}, log::Level::debug, "{}", msg);
    }

    void enable_gnutls_logging(int level)
    {
        gnutls_global_set_log_level(level);
        gnutls_global_set_log_function(gnutls_log);
    }
#endif

    void generate_reset_token(
            std::span<const uint8_t> static_secret,
            const ngtcp2_cid* cid,
            std::span<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> out)
    {
        if (ngtcp2_crypto_generate_stateless_reset_token(out.data(), static_secret.data(), static_secret.size(), cid) != 0)
            throw std::runtime_error{"Failed to generate stateless reset token!"};
    }
    void generate_reset_token(
            std::span<const uint8_t> static_secret,
            const quic_cid& cid,
            std::span<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> out)
    {
        generate_reset_token(static_secret, cid.ngtcp2(), out);
    }
    std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> generate_reset_token(
            std::span<const uint8_t> static_secret, const ngtcp2_cid* cid)
    {
        std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token;
        generate_reset_token(static_secret, cid, token);
        return token;
    }
    std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> generate_reset_token(
            std::span<const uint8_t> static_secret, const quic_cid& cid)
    {
        return generate_reset_token(static_secret, cid.ngtcp2());
    }

    static constexpr auto STATELESS_HASH_PREFIX = "quic stateless reset hash"sv;
    hashed_reset_token::hashed_reset_token(
            std::span<const uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token, std::span<const uint8_t> static_secret)
    {
        // SHAKE256(STATELESS_HASH_PREFIX || static_secret || token)
        sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_update(&ctx, STATELESS_HASH_PREFIX.size(), reinterpret_cast<const uint8_t*>(STATELESS_HASH_PREFIX.data()));
        sha3_256_update(&ctx, static_secret.size(), static_secret.data());
        sha3_256_update(&ctx, token.size(), token.data());
        sha3_256_shake(&ctx, size(), data());
    }

    static std::string translate_key_format(gnutls_x509_crt_fmt_t crt)
    {
        if (crt == GNUTLS_X509_FMT_DER)
            return "<< DER >>";
        if (crt == GNUTLS_X509_FMT_PEM)
            return "<< PEM >>";

        return "<< UNKNOWN >>";
    }

    // Return value: 0 is pass, non-zero to terminate.
    extern "C" int cert_verify_callback_gnutls(gnutls_session_t session)
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& conn = GNUTLSSession::conn_from(session);

        GNUTLSSession& tls_session = GNUTLSSession::from(conn);

        bool success = tls_session.validate_remote_key();

        if (success)
            log::debug(log_cat, "{} certificate validated successfully", conn.is_outbound() ? "Server" : "Client");
        else
            log::error(
                    log_cat,
                    "{} certificate validation failed; rejecting connection",
                    conn.is_outbound() ? "Server" : "Client");

        return success ? 0 : 1;
    }

    void GNUTLSCreds::load_keys(x509_loader& s, x509_loader& pk)
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        int rv = 0;

        if (rv = gnutls_pcert_import_rawpk_raw(&pcrt, &pk.mem, pk.format, 0, 0); rv != 0)
            log::warning(log_cat, "Pcert import failed!");

        if (rv |= gnutls_privkey_init(&pkey); rv != 0)
            log::warning(log_cat, "Privkey init failed!");

        if (rv |= gnutls_privkey_import_x509_raw(pkey, &s.mem, s.format, NULL, 0); rv != 0)
            log::warning(log_cat, "Privkey import failed!");
    }

    static constexpr auto* PRIORITY =
            "NORMAL:+ECDHE-PSK:+PSK:+ECDHE-ECDSA:+AES-128-CCM-8:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL:+SHA256";

    GNUTLSCreds::GNUTLSCreds()
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");
        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        const char* err{nullptr};
        if (auto rv = gnutls_priority_init(&priority_cache, PRIORITY, &err); rv < 0)
        {
            if (rv == GNUTLS_E_INVALID_REQUEST)
                log::warning(log_cat, "gnutls_priority_init error: {}", err);
            else
                log::warning(log_cat, "gnutls_priority_init error: {}", gnutls_strerror(rv));

            throw std::runtime_error("gnutls key exchange algorithm priority setup failed");
        }

        gnutls_certificate_set_verify_function(cred, cert_verify_callback_gnutls);
    }

    GNUTLSCreds::GNUTLSCreds(std::string_view ed_seed, std::string_view ed_pubkey) : GNUTLSCreds{}
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");

        constexpr auto pem_fmt = "-----BEGIN {0} KEY-----\n{1}\n-----END {0} KEY-----\n"sv;

        auto seed = x509_loader{
                fmt::format(pem_fmt, "PRIVATE", oxenc::to_base64("{}{}"_format(ASN_ED25519_SEED_PREFIX, ed_seed)))};

        auto pubkey = x509_loader{
                fmt::format(pem_fmt, "PUBLIC", oxenc::to_base64("{}{}"_format(ASN_ED25519_PUBKEY_PREFIX, ed_pubkey)))};

        assert(seed.from_mem() && pubkey.from_mem());
        assert(seed.format == pubkey.format);

        log::debug(log_cat, "Seed and pubkey format: {}", translate_key_format(pubkey.format));

        // LOAD KEYS HERE
        load_keys(seed, pubkey);
        has_creds = true;

        if (auto rv = gnutls_certificate_set_key(cred, NULL, 0, &pcrt, 1, pkey); rv < 0)
        {
            log::warning(log_cat, "gnutls import of raw Ed keys failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls import of raw Ed keys failed");
        }
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        if (anti_replay)
            gnutls_anti_replay_deinit(anti_replay);
        if (cred)
            gnutls_certificate_free_credentials(cred);
        if (priority_cache)
            gnutls_priority_deinit(priority_cache);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string_view seed, std::string_view pubkey)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds{seed, pubkey}};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_seckey(std::string_view sk)
    {
        if (sk.size() != GNUTLS_SECRET_KEY_SIZE)
            throw std::invalid_argument("Ed25519 secret key is invalid length!");

        auto pk = sk.substr(GNUTLS_KEY_SIZE);
        sk = sk.substr(0, GNUTLS_KEY_SIZE);

        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds{sk, pk}};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_unauthenticated()
    {
        return std::shared_ptr<GNUTLSCreds>(new GNUTLSCreds{});
    }

    void GNUTLSCreds::require_client_keys(key_verify_callback cb)
    {
        client_key_verify = std::move(cb);
        ccert_required = true;
        ccert_requested = false;
    }

    void GNUTLSCreds::request_client_keys(key_verify_callback cb)
    {
        client_key_verify = std::move(cb);
        ccert_required = false;
        ccert_requested = true;
    }

    void GNUTLSCreds::disable_client_keys()
    {
        client_key_verify = nullptr;
        ccert_required = ccert_requested = false;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(
            Connection& c,
            const IOContext& ctx,
            std::span<const std::string> alpns,
            std::optional<std::span<const unsigned char>> expected_key)
    {
        std::optional<gtls_key> exp_key;
        if (expected_key)
        {
            if (expected_key->size() != GNUTLS_KEY_SIZE)
                throw std::invalid_argument{"Invalid GNUTLS expected pubkey"};
            std::memcpy(exp_key.emplace().data(), expected_key->data(), expected_key->size());
        }
        return std::make_unique<GNUTLSSession>(*this, ctx, c, alpns, std::move(exp_key));
    }

    int anti_replay_store(void* creds_ptr, time_t exp_time, const gnutls_datum_t* key, const gnutls_datum_t* data)
    {
        assert(creds_ptr);
        auto& creds = *static_cast<GNUTLSCreds*>(creds_ptr);
        assert(creds.anti_replay_add);
        bool accepted;
        try
        {
            accepted = creds.anti_replay_add(
                    std::span<const unsigned char>{key->data, key->size},
                    std::span<const unsigned char>{data->data, data->size},
                    std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::from_time_t(exp_time)));
            log::debug(log_cat, "anti-replay storage {} incoming key", accepted ? "accepted" : "REJECTED");
        }
        catch (const std::exception& e)
        {
            log::critical(log_cat, "anti replay function raised an exception (); anti-replay protection may be DISABLED");
            accepted = true;
        }
        return accepted ? 0 : GNUTLS_E_DB_ENTRY_EXISTS;
    }

    GNUTLSCreds::anti_replay_add_cb default_anti_replay_add()
    {

        return [last_cleanup = std::chrono::system_clock::now(),
                storage = std::unordered_map<
                        std::string,
                        std::pair<std::vector<unsigned char>, std::chrono::system_clock::time_point>>{}](
                       std::span<const unsigned char> key,
                       std::span<const unsigned char> value,
                       std::chrono::system_clock::time_point expiry) mutable -> bool {
            log::debug(
                    log_cat, "Storing 0-RTT anti-replay ticket for key {}", oxenc::to_hex(std::begin(key), std::end(key)));
            auto accepted = storage.try_emplace(
                                           std::string{reinterpret_cast<const char*>(key.data()), key.size()},
                                           std::piecewise_construct,
                                           std::forward_as_tuple(value.begin(), value.end()),
                                           std::forward_as_tuple(expiry))
                                    .second;

            // Clean cache at most once/s:
            if (auto now = std::chrono::system_clock::now(); now > last_cleanup + 1s)
            {
                std::erase_if(storage, [&now](const auto& p) { return p.second.second < now; });
                last_cleanup = now;
            }

            return accepted;
        };
    }

    void GNUTLSCreds::enable_inbound_0rtt(
            std::chrono::milliseconds anti_replay_window,
            std::chrono::seconds ticket_validity,
            size_t max_early,
            anti_replay_add_cb anti_replay_add_,
            std::span<const unsigned char> master_key)
    {
        if (inbound_0rtt())
            throw std::logic_error{"Inbound 0-RTT is already enabled for this GNUTLSCreds instance"};

        if (max_early == 0)
            max_early_data = 32_ki;
        else
            max_early_data = max_early;

        session_ticket_key.sensitive = true;
        session_ticket_key.reset();
        if (!master_key.empty())
        {
            if (!anti_replay_add_)
                throw std::logic_error{
                        "GNUTLSCreds 0rtt master_key can only be used with a custom anti_replay_add function"};
            session_ticket_key.allocate(master_key.size());
            std::memcpy(session_ticket_key.data(), master_key.data(), master_key.size());
        }
        else
        {
            int rv = gnutls_session_ticket_key_generate(session_ticket_key);
            if (rv != GNUTLS_E_SUCCESS)
                throw std::runtime_error{
                        "GNUTLS failed to generate a session ticket master key: {}"_format(gnutls_strerror(rv))};
        }

        session_ticket_expiration = std::max(ticket_validity, 0s).count();

        if (anti_replay)
            gnutls_anti_replay_deinit(anti_replay);
        gnutls_anti_replay_init(&anti_replay);
        gnutls_anti_replay_set_ptr(anti_replay, this);
        gnutls_anti_replay_set_add_function(anti_replay, anti_replay_store);
        gnutls_anti_replay_set_window(
                anti_replay, (anti_replay_window > 0ms ? anti_replay_window : DEFAULT_ANTI_REPLAY_WINDOW).count());
        anti_replay_add = std::move(anti_replay_add_);
        if (!anti_replay_add)
            anti_replay_add = default_anti_replay_add();

        log::debug(log_cat, "0-RTT support enabled for inbound connections");
    }

    std::vector<unsigned char> GNUTLSCreds::create_0rtt_master_key()
    {
        gtls_datum key;
        key.sensitive = true;
        gnutls_session_ticket_key_generate(key);
        std::vector<unsigned char> result;
        result.resize(key.size());
        std::memcpy(result.data(), key.data(), key.size());
        return result;
    }

    std::pair<store_callback, extract_callback> default_store_extract_callbacks()
    {
        std::pair<store_callback, extract_callback> result;
        auto storage = std::make_shared<std::unordered_map<
                RemoteAddress,
                std::deque<std::pair<std::vector<unsigned char>, std::chrono::system_clock::time_point>>>>();
        result.first = [storage](
                               const RemoteAddress& remote,
                               std::vector<unsigned char> data,
                               std::chrono::system_clock::time_point expiry) {
            log::debug(log_cat, "Storing 0-RTT session data for remote {}", remote);
            auto& mine = (*storage)[remote];
            while (mine.size() > 2)
                mine.pop_front();
            mine.emplace_back(std::move(data), expiry);
        };
        result.second =
                [storage = std::move(storage)](const RemoteAddress& remote) -> std::optional<std::vector<unsigned char>> {
            log::debug(log_cat, "Looking up 0-RTT session data for remote {}", remote);
            std::optional<std::vector<unsigned char>> result;
            auto it = storage->find(remote);
            if (it == storage->end())
            {
                log::debug(log_cat, "No 0-RTT session data found");
                return result;
            }

            auto& mine = it->second;
            auto now = std::chrono::system_clock::now();
            // We track these in order, but it's possible that earlier tickets have a longer
            // expiry, so try the tail first but then work back towards the head until we find
            // something (or run out of tickets).
            while (!mine.empty() && mine.back().second <= now)
            {
                log::trace(log_cat, "Dropping expired 0-RTT session data");
                mine.pop_back();
            }
            if (!mine.empty())
            {
                result = std::move(mine.back().first);
                log::debug(
                        log_cat,
                        "Found 0-RTT session data with expiry +{}s; {} session data remaining",
                        std::chrono::duration_cast<std::chrono::seconds>(mine.back().second - now).count(),
                        mine.size() - 1);
                mine.pop_back();
            }
            if (mine.empty())
                storage->erase(it);

            return result;
        };

        return result;
    }

    void GNUTLSCreds::enable_outbound_0rtt(store_callback store, extract_callback extract)
    {
        if (outbound_0rtt())
            throw std::logic_error{"Inbound 0-RTT is already enabled for this GNUTLSCreds instance"};

        if (bool(store) != bool(extract))
            throw std::logic_error{"GNUTLSCreds::enable_outbound_0rtt: store and extract callbacks are mutually dependent"};

        if (!store)
        {
            std::tie(store, extract) = default_store_extract_callbacks();
        }

        session_store = std::move(store);
        session_extract = std::move(extract);
        log::debug(log_cat, "0-RTT support enabled for outbound connections");
    }
    void GNUTLSCreds::enable_outbound_0rtt()
    {
        enable_outbound_0rtt(nullptr, nullptr);
    }

    void GNUTLSCreds::store_session_ticket(Connection& conn, RemoteAddress addr, std::span<const unsigned char> ticket_data)
    {
        log::trace(log_cat, "Received session ticket data from remote {}", addr);
        if (!session_store)
        {
            log::debug(log_cat, "No 0-RTT storage callback, ignoring session ticket data");
            return;
        }

        std::array<unsigned char, 512> quic_tp;
        auto tp_size = ngtcp2_conn_encode_0rtt_transport_params(conn, quic_tp.data(), quic_tp.size());
        if (tp_size < 0)
        {
            log::error(
                    log_cat,
                    "Unable to store session ticket: connection quic 0rtt transport param encoding failed ({})",
                    ngtcp2_strerror(tp_size));
            return;
        }

        gnutls_datum_t gticket_data{
                const_cast<unsigned char*>(ticket_data.data()), static_cast<unsigned int>(ticket_data.size())};
        auto expiry = std::chrono::time_point_cast<std::chrono::seconds>(
                std::chrono::system_clock::from_time_t(gnutls_db_check_entry_expire_time(&gticket_data)));
        if (expiry.time_since_epoch() == 0s)
        {
            log::error(log_cat, "Unable to store session ticket: failed to extract expiry time from TLS session ticket");
            return;
        }

        // bt-encode the session ticket and the encoded quic parameters for the storage callback:
        std::vector<unsigned char> session_data;

        // Calculate the exact length we require for encoding the two buffer lengths:
        size_t ticketlen_encoded = 2;  // `0:` minimum
        for (size_t x = ticket_data.size() / 10; x; x /= 10)
            ticketlen_encoded++;
        size_t tplen_encoded = tp_size >= 100 ? 4 : tp_size >= 10 ? 3 : 2;  // 512:, 42:, or 8:
        session_data.resize(1 /*l*/ + ticketlen_encoded + ticket_data.size() + tplen_encoded + tp_size + 1 /*e*/);

        {
            oxenc::bt_list_producer prod{reinterpret_cast<char*>(session_data.data()), session_data.size()};
            prod.append(std::string_view{reinterpret_cast<const char*>(ticket_data.data()), ticket_data.size()});
            prod.append(std::string_view{reinterpret_cast<const char*>(quic_tp.data()), static_cast<size_t>(tp_size)});
            assert(prod.view().size() == session_data.size());
        }

        try
        {
            session_store(std::move(addr), std::move(session_data), expiry);
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "Session ticket storage callback raised an exception: {}", e.what());
        }
    }

    std::optional<session_data> GNUTLSCreds::extract_session_data(const RemoteAddress& remote)
    {
        std::optional<session_data> result;

        log::trace(log_cat, "0-RTT session data request for remote {}", remote);
        if (!session_extract)
            return result;
        std::optional<std::vector<unsigned char>> data;
        try
        {
            data = session_extract(remote);
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "0-RTT extraction callback raised an exception: {}", e.what());
            return result;
        }
        if (!data || data->empty())
        {
            log::debug(log_cat, "No stored 0-RTT session data for {}", remote);
            return result;
        }

        try
        {
            oxenc::bt_list_consumer cons{std::string_view{reinterpret_cast<const char*>(data->data()), data->size()}};
            auto tls_in = cons.consume_string_view();
            auto tp_in = cons.consume_string_view();
            if (!cons.is_finished())
                throw std::runtime_error{"Unexpected extra content in extracted session data"};
            if (tls_in.empty() || tp_in.empty())
            {
                log::debug(
                        log_cat,
                        "Retrieved empty {} data; 0-RTT declined",
                        tls_in.empty() ? tp_in.empty() ? "TLS & transport" : "TLS" : "transport");
                return result;
            }
            auto& out = result.emplace();
            out.tls_session_ticket.resize(tls_in.size());
            std::memcpy(out.tls_session_ticket.data(), tls_in.data(), tls_in.size());
            out.quic_transport_params.resize(tp_in.size());
            std::memcpy(out.quic_transport_params.data(), tp_in.data(), tp_in.size());
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "Failed to parse 0-RTT session data: {}", e.what());
        }
        return result;
    }

    namespace
    {
        constexpr std::string_view translate_cert_type(gnutls_certificate_type_t type)
        {
            switch (static_cast<int>(type))
            {
                case 1:
                    return "<< X509 Cert >>"sv;
                case 2:
                    return "<< OpenPGP Cert >>"sv;
                case 3:
                    return "<< Raw PK Cert >>"sv;
                case 0:
                default:
                    return "<< Unknown Type >>"sv;
            }
        }

        std::string_view get_cert_type(gnutls_session_t session, gnutls_ctype_target_t type)
        {
            return translate_cert_type(gnutls_certificate_type_get2(session, type));
        }

    }  // namespace

    extern "C" int client_session_cb(
            gnutls_session_t session,
            unsigned int htype,
            unsigned /* when */,
            unsigned int /* incoming */,
            const gnutls_datum_t* /* msg */)
    {
        if (htype == GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
        {
            auto& conn = GNUTLSSession::conn_from(session);

            RemoteAddress remote{conn.remote_key(), conn.remote()};
            log::debug(log_cat, "received new tls session ticket from: {}", remote);

            gtls_datum data;
            if (auto rv = gnutls_session_get_data2(session, data); rv != 0)
            {
                log::warning(log_cat, "Failed to query session data: {}", gnutls_strerror(rv));
                return rv;
            }

            conn.get_creds()->store_session_ticket(conn, remote, std::span<const unsigned char>{data.data(), data.size()});
        }

        return 0;
    }

    GNUTLSSession& GNUTLSSession::from(gnutls_session_t g_session)
    {
        return from(conn_from(g_session));
    }

    GNUTLSSession& GNUTLSSession::from(Connection& conn)
    {
        auto* sess = conn.get_session();
        assert(dynamic_cast<GNUTLSSession*>(sess));
        return *static_cast<GNUTLSSession*>(sess);
    }

    Connection& GNUTLSSession::conn_from(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        return *conn;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    struct IOContext;
    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            const IOContext& /*ctx*/,
            Connection& c,
            std::span<const std::string> alpns,
            std::optional<gtls_key> expected_key) :
            creds{creds}, _is_client{c.is_outbound()}, _expected_remote_key{std::move(expected_key)}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        const auto direction_string = _is_client ? "Client"sv : "Server"sv;
        log::trace(log_cat, "Creating {} GNUTLSSession", direction_string);

        uint32_t init_flags = _is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;

        // We send session tickets manually after QUIC handshake completes (if using 0rtt), as per
        // RFC 9001:
        init_flags |= GNUTLS_NO_AUTO_SEND_TICKET;

        const bool use_0rtt = _is_client ? creds.outbound_0rtt() : creds.inbound_0rtt();
        if (use_0rtt)
        {
            log::debug(log_cat, "Enabling early data for 0-RTT");
            init_flags |= GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA;
        }

        // DISCUSS: we actually don't want to do this if the requested certificate is expecting
        // x509 (see gnutls_creds.cpp::cert_retrieve_callback_gnutls function body)
        if (creds.using_raw_pk)
        {
            log::debug(log_cat, "Setting GNUTLS_ENABLE_RAWPK flag on gnutls_init");
            init_flags |= GNUTLS_ENABLE_RAWPK;
        }

        if (auto rv = gnutls_init(&session, init_flags); rv < 0)
        {
            log::error(log_cat, "{} gnutls_init failed: {}", direction_string, gnutls_strerror(rv));
            throw std::runtime_error("{} gnutls_init failed"_format(direction_string));
        }

        if (creds.using_raw_pk)
        {
            // NB: creds.priority_cache currently includes +CTYPE-CLI-ALL:+CTYPE-SRV-ALL which are
            // needed for raw_pk.  It isn't entirely clear if that is perfectly fine without raw_pk
            // mode, which is why this priority set call is inside this if(raw_pk) block.
            if (auto rv = gnutls_priority_set(session, creds.priority_cache); rv < 0)
            {
                log::error(log_cat, "gnutls_priority_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_priority_set failed");
            }
        }
        else if (auto rv = gnutls_set_default_priority(session); rv < 0)
        {
            log::error(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_set_default_priority failed");
        }

        log::debug(
                log_cat,
                "[GNUTLS SESSION] Local ({}) cert type:{} \t Peer expecting cert type:{}",
                _is_client ? "CLIENT" : "SERVER",
                get_cert_type(session, GNUTLS_CTYPE_OURS),
                get_cert_type(session, GNUTLS_CTYPE_PEERS));

        if (not _is_client)
        {
            log::trace(log_cat, "gnutls configuring server session...");

            if (use_0rtt)
            {
                log::debug(log_cat, "Configuring gnutls for 0-RTT");
                if (creds.session_ticket_expiration > 0)
                    gnutls_db_set_cache_expiration(session, creds.session_ticket_expiration);

                gnutls_anti_replay_enable(session, creds.anti_replay);
                gnutls_record_set_max_early_data_size(session, creds.max_early_data);
                if (auto rv = gnutls_session_ticket_enable_server(session, creds.session_ticket_key); rv != 0)
                    log::error(
                            log_cat,
                            "gnutls_session_ticket_enable_server failed: {}; 0-RTT will not be available for this "
                            "connection",
                            gnutls_strerror(rv));
            }

            if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }

            if (creds.ccert_required || creds.ccert_requested)
                gnutls_certificate_server_set_request(
                        session, creds.ccert_required ? GNUTLS_CERT_REQUIRE : GNUTLS_CERT_REQUEST);
        }
        else
        {
            log::trace(log_cat, "gnutls configuring client session...");

            if (use_0rtt)
            {
                log::trace(log_cat, "Setting client session ticket db hook...");
                gnutls_handshake_set_hook_function(
                        session, GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, GNUTLS_HOOK_POST, client_session_cb);
            }

            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }

            if (use_0rtt && _expected_remote_key)
            {
                RemoteAddress remote{*_expected_remote_key, c.remote()};
                if (auto maybe_session = creds.extract_session_data(remote))
                {
                    auto& [tls_ticket, quic_tp] = *maybe_session;
                    if (auto rv = gnutls_session_set_data(session, tls_ticket.data(), tls_ticket.size()); rv != 0)
                        log::warning(
                                log_cat,
                                "Invalid session ticket data ({}); 0-RTT disabled for connection",
                                gnutls_strerror(rv));
                    else
                    {
                        log::debug(log_cat, "TLS session ticket data loaded for 0-RTT");
                        // This TLSSession is created during Connection construction *before* we
                        // have an ngtcp2 conn, so we can't set this data yet: instead we stash it
                        // for Connection to deal with later in the Connection construction.
                        _0rtt_tp_data = std::move(quic_tp);
                    }
                }
                else
                {
                    log::debug(log_cat, "No session data found for {}, 0-RTT will not be used.", remote);
                }
            }
        }

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds.cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_credentials_set failed");
        }

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (_is_client)
        {
            if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            {
                log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_server_name_set failed");
            }
        }

        std::string def_alpn;
        if (alpns.empty())
        {
            def_alpn = default_alpn_str;
            alpns = {&def_alpn, 1};
        }
        std::vector<gnutls_datum_t> allowed_alpns;
        for (auto& s : alpns)
        {
            log::trace(log_cat, "GNUTLS adding \"{}\" to {} ALPNs", s, direction_string);
            allowed_alpns.emplace_back(gnutls_datum_t{
                    reinterpret_cast<unsigned char*>(const_cast<char*>(s.data())), static_cast<unsigned int>(s.size())});
        }

        if (auto rv = gnutls_alpn_set_protocols(session, &allowed_alpns[0], allowed_alpns.size(), GNUTLS_ALPN_MANDATORY);
            rv < 0)
        {
            log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_alpn_set_protocols failed");
        }
    }

    void GNUTLSSession::send_session_tickets()
    {
        log::trace(log_cat, "sending tls session tickets");
        if (auto rv = gnutls_session_ticket_send(session, 2, 0); rv != 0)
            log::error(log_cat, "gnutls_session_ticket_send failed: {}", gnutls_strerror(rv));
    }

    void GNUTLSSession::load_selected_alpn()
    {
        gnutls_datum_t _alpn{};
        if (auto rv = gnutls_alpn_get_selected_protocol(session, &_alpn); rv < 0)
        {
            auto err = "ALPN negotiation incomplete";
            log::error(log_cat, "{}", err);
            throw std::logic_error{err};
        }
        _selected_alpn = {reinterpret_cast<const char*>(_alpn.data), _alpn.size};
        _loaded_alpn = true;
    }

    void GNUTLSSession::load_remote_key()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        _loaded_remote_key = true;

        assert(creds.using_raw_pk);

        const auto local_name = _is_client ? "CLIENT"sv : "SERVER"sv;

        log::debug(
                log_cat,
                "Local ({}) cert type:{} \t Peer expecting cert type:{}",
                local_name,
                get_cert_type(session, GNUTLS_CTYPE_OURS),
                get_cert_type(session, GNUTLS_CTYPE_PEERS));

        auto cert_type = gnutls_certificate_type_get2(session, GNUTLS_CTYPE_PEERS);

        uint32_t cert_list_size = 0;
        const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

        // The peer did not return a certificate
        if (cert_list_size == 0)
        {
            log::debug(log_cat, "Quic {} called {}, but peer's cert list is empty.", local_name, __PRETTY_FUNCTION__);
            return;
        }

        // this function is only for raw pubkey mode, and should not be called otherwise
        if (cert_type != GNUTLS_CRT_RAWPK)
        {
            log::warning(
                    log_cat,
                    "{} called, but remote cert type is not raw pubkey (type: {}).",
                    __PRETTY_FUNCTION__,
                    translate_cert_type(cert_type));
            return;
        }

        if (cert_list_size != 1)
            log::debug(
                    log_cat,
                    "Quic {} received peers cert list with more than one entry; choosing first item and proceeding...",
                    local_name);

        const auto* cert_data = cert_list[0].data + CERT_HEADER_SIZE;
        auto cert_size = cert_list[0].size - CERT_HEADER_SIZE;

        log::trace(
                log_cat,
                "Quic {} validating pubkey \"cert\" of len {}B:\n{}\n",
                local_name,
                cert_size,
                buffer_printer{std::span{cert_data, cert_size}});

        // pubkey comes as 12 bytes header + 32 bytes key
        if (cert_size != GNUTLS_KEY_SIZE)
        {
            log::warning(log_cat, "Rejecting remote key: invalid key size {} != expected {}", cert_size, GNUTLS_KEY_SIZE);
            return;
        }

        std::memcpy(_remote_key.emplace().data(), cert_data, cert_size);
    }

    std::span<const unsigned char> GNUTLSSession::remote_key()
    {
        if (!_loaded_remote_key)
            load_remote_key();
        if (_remote_key)
            return *_remote_key;
        return {};
    }

    std::string_view GNUTLSSession::selected_alpn()
    {
        if (!_loaded_alpn)
            load_selected_alpn();
        return _selected_alpn;
    }

    // Called to verify a remote key during connection establishing *if* a remote key is provided:
    // - server must always provide a key
    // - clients must provide a key if require_client_keys() was called on the server, and may
    //   provide one if request_client_keys() was called on the server, and otherwise don't provide
    //   one.
    //
    // 0-RTT connections (which are resumption of an earlier connection) do not call this at all.
    //
    //  Return values:
    //       true: The connection is accepted and marked "validated"
    //       false: The connection is refused
    //
    bool GNUTLSSession::validate_remote_key()
    {
        load_remote_key();
        load_selected_alpn();

        if (_is_client)
        {
            // Client does validation through a remote pubkey provided when calling endpoint::connect
            bool success = !_expected_remote_key || *_remote_key == _expected_remote_key;
            if (success)
                log::debug(log_cat, "Client successfully validated server pubkey; accepting connection");
            else
                log::warning(
                        log_cat,
                        "Mismatch during server pubkey verification: expected {}, got {}",
                        oxenc::to_hex(_expected_remote_key->begin(), _expected_remote_key->end()),
                        oxenc::to_hex(_remote_key->begin(), _remote_key->end()));
            return success;
        }

        // Server does validation through optional callback
        if (!_remote_key && creds.ccert_required)
        {
            log::debug(log_cat, "Rejecting incoming connection: required client key not provided");
            return false;
        }
        if (!creds.client_key_verify)
        {
            log::debug(log_cat, "Accepting incoming connection with pubkey (without key verification callback)");
            return true;
        }
        bool success = creds.client_key_verify(remote_key(), selected_alpn());
        log::debug(log_cat, "Key verify callback {} incoming connection", success ? "accepted" : "rejected");
        return success;
    }

}  //  namespace oxen::quic
