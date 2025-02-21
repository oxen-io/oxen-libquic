#include "connection.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"

#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

#include <chrono>
#include <tuple>
#include <utility>

namespace oxen::quic
{
    static std::string translate_key_format(gnutls_x509_crt_fmt_t crt)
    {
        if (crt == GNUTLS_X509_FMT_DER)
            return "<< DER >>";
        if (crt == GNUTLS_X509_FMT_PEM)
            return "<< PEM >>";

        return "<< UNKNOWN >>";
    }

    // Return value: 0 is pass, negative is fail
    extern "C" int cert_verify_callback_gnutls(gnutls_session_t session)
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& conn = GNUTLSSession::conn_from(session);

        GNUTLSSession& tls_session = GNUTLSSession::from(conn);

        auto local_name = (conn.is_outbound()) ? "CLIENT" : "SERVER";

        //  true: Peer provided a valid cert; connection is accepted and marked validated
        //  false: Peer either provided an invalid cert or no cert; connection is rejected
        bool success = tls_session.validate_remote_key();
        if (success)
            conn.set_validated();

        auto err = "Quic {} was {}able to validate peer certificate; {} connection!"_format(
                local_name, success ? "" : "un", success ? "accepting" : "rejecting");

        if (success)
            log::debug(log_cat, "{}", err);
        else
            log::error(log_cat, "{}", err);

        return !success;
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

    GNUTLSCreds::GNUTLSCreds(std::string_view ed_seed, std::string_view ed_pubkey) : using_raw_pk{true}
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

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        [[maybe_unused]] constexpr auto usage_flags = GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_NON_REPUDIATION |
                                                      GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DATA_ENCIPHERMENT |
                                                      GNUTLS_KEY_KEY_AGREEMENT | GNUTLS_KEY_KEY_CERT_SIGN;

        if (auto rv = gnutls_certificate_set_key(cred, NULL, 0, &pcrt, 1, pkey); rv < 0)
        {
            log::warning(log_cat, "gnutls import of raw Ed keys failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls import of raw Ed keys failed");
        }

        // clang format keeps changing this arbitrarily, so disable for this line
        // clang-format off
        constexpr auto* priority = "NORMAL:+ECDHE-PSK:+PSK:+ECDHE-ECDSA:+AES-128-CCM-8:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL:+SHA256";
        // clang-format on

        const char* err{nullptr};
        if (auto rv = gnutls_priority_init(&priority_cache, priority, &err); rv < 0)
        {
            if (rv == GNUTLS_E_INVALID_REQUEST)
                log::warning(log_cat, "gnutls_priority_init error: {}", err);
            else
                log::warning(log_cat, "gnutls_priority_init error: {}", gnutls_strerror(rv));

            throw std::runtime_error("gnutls key exchange algorithm priority setup failed");
        }

        gnutls_certificate_set_verify_function(cred, cert_verify_callback_gnutls);
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        if (anti_replay)
            gnutls_anti_replay_deinit(anti_replay);
        gnutls_certificate_free_credentials(cred);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string_view seed, std::string_view pubkey)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(seed, pubkey)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_seckey(std::string_view sk)
    {
        if (sk.size() != GNUTLS_SECRET_KEY_SIZE)
            throw std::invalid_argument("Ed25519 secret key is invalid length!");

        auto pk = sk.substr(GNUTLS_KEY_SIZE);
        sk = sk.substr(0, GNUTLS_KEY_SIZE);

        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(sk, pk)};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(
            Connection& c,
            const IOContext& ctx,
            std::span<const std::string> alpns,
            std::optional<std::span<const unsigned char>> expected_key)
    {
        std::optional<gtls_key> exp_key;
        if (expected_key)
            exp_key.emplace(*expected_key);
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
                    std::chrono::system_clock::from_time_t(exp_time));
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
            anti_replay_add_cb anti_replay_add_,
            std::span<const unsigned char> master_key)
    {
        if (inbound_0rtt())
            throw std::logic_error{"Inbound 0-RTT is already enabled for this GNUTLSCreds instance"};

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
        auto expiry = std::chrono::system_clock::from_time_t(gnutls_db_check_entry_expire_time(&gticket_data));
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

}  // namespace oxen::quic
