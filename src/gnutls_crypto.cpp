#include "gnutls_crypto.hpp"

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
}

#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <stdexcept>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"

namespace oxen::quic
{
    GNUTLSSession* get_session_from_gnutls(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
        assert(tls_session);
        return tls_session;
    }

    extern "C"
    {
        int gnutls_callback_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            auto* tls_session = get_session_from_gnutls(session);
            assert(tls_session->get_session() == session);

            return tls_session->do_tls_callback(session, htype, when, incoming, msg);
        }

        int cert_verify_callback_gnutls(gnutls_session_t g_session)
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            auto* tls_session = get_session_from_gnutls(g_session);
            assert(tls_session->get_session() == g_session);

            // 0 is pass, negative is fail
            return tls_session->validate_remote_key() ? 0 : -1;
        }

        void gnutls_log(int level, const char* str)
        {
            log::debug(log_cat, "GNUTLS Log (level {}): {}", level, str);
        }
    }

    struct gnutls_log_setter
    {
        gnutls_log_setter()
        {
            gnutls_global_set_log_level(99);
            gnutls_global_set_log_function(gnutls_log);
        }
    };

    // uncomment to enable gnutls logging; set level above.
    // inline static const gnutls_log_setter gls{};

    GNUTLSCreds::GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg)
    {
        if (local_key.empty() || local_cert.empty())
            throw std::runtime_error{
                    "Must initialize GNUTLS credentials using local private key and certificate at minimum"};

        x509_loader lkey{local_key};
        x509_loader lcert{local_cert};
        x509_loader rcert;
        if (not remote_cert.empty())
            rcert = {remote_cert};
        x509_loader ca;
        if (not ca_arg.empty())
            ca = {ca};

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        if (ca)
        {
            if (auto rv = (ca.from_mem()) ? gnutls_certificate_set_x509_trust_mem(cred, ca, ca.format)
                                          : gnutls_certificate_set_x509_trust_file(cred, ca, ca.format);
                rv < 0)
            {
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
                throw std::invalid_argument("gnutls didn't like a specified trust file/memblock");
            }
        }

        if (auto rv = (lcert.from_mem()) ? gnutls_certificate_set_x509_key_mem(cred, lcert, lkey, lkey.format)
                                         : gnutls_certificate_set_x509_key_file(cred, lcert, lkey, lkey.format);
            rv < 0)
        {
            log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
            throw std::invalid_argument("gnutls didn't like a specified key file/memblock");
        }

        log::info(log_cat, "Completed credential initialization");
    }

    // These bytes mean "this is a raw Ed25519 private key" in ASN.1 (or something like that)
    static const std::string ASN_ED25519_SEED_PREFIX = oxenc::from_hex("302e020100300506032b657004220420"sv);
    // These bytes mean "this is a raw Ed25519 public key" in ASN.1 (or something like that)
    static const std::string ASN_ED25519_PUBKEY_PREFIX = oxenc::from_hex("302a300506032b6570032100"sv);

    GNUTLSCreds::GNUTLSCreds(std::string ed_seed, std::string ed_pubkey) : using_raw_pk{true}
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");

        constexpr auto pem_fmt = "-----BEGIN {0} KEY-----\n{1}\n-----END {0} KEY-----\n"sv;

        x509_loader seed{fmt::format(pem_fmt, "PRIVATE", oxenc::to_base64(ASN_ED25519_SEED_PREFIX + ed_seed))};

        x509_loader pubkey{fmt::format(pem_fmt, "PUBLIC", oxenc::to_base64(ASN_ED25519_PUBKEY_PREFIX + ed_pubkey))};

        assert(seed.from_mem() && pubkey.from_mem());
        assert(seed.format == pubkey.format);

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        constexpr auto usage_flags = GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_NON_REPUDIATION |
                                     GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DATA_ENCIPHERMENT | GNUTLS_KEY_KEY_AGREEMENT |
                                     GNUTLS_KEY_KEY_CERT_SIGN;

        // FIXME: the key usage parameter (6th) is weird.  Since we only have the one keypair and
        //        we're only using it for ECDH, setting it to "use key for anything" should be fine.
        //        I believe the value for this is 0, and if it works it works.
        if (auto rv = gnutls_certificate_set_rawpk_key_mem(
                    cred, pubkey, seed, seed.format, nullptr, usage_flags, nullptr, 0, 0);
            rv < 0)
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
                log::error(log_cat, "gnutls_priority_init error: {}", err);
            else
                log::error(log_cat, "gnutls_priority_init error: {}", gnutls_strerror(rv));

            throw std::runtime_error("gnutls key exchange algorithm priority setup failed");
        }

        gnutls_certificate_set_verify_function(cred, cert_verify_callback_gnutls);
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_certificate_free_credentials(cred);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make(
            std::string remote_key, std::string remote_cert, std::string local_cert, std::string ca)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(remote_key, remote_cert, local_cert, ca)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string seed, std::string pubkey)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(seed, pubkey)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_seckey(std::string sk)
    {
        if (sk.size() != GNUTLS_SECRET_KEY_SIZE)
            throw std::invalid_argument("Ed25519 secret key is invalid length!");

        auto pk = sk.substr(GNUTLS_KEY_SIZE);
        sk = sk.substr(0, GNUTLS_KEY_SIZE);

        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(std::move(sk), std::move(pk))};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(bool is_client, const std::vector<std::string>& alpns)
    {
        return std::make_unique<GNUTLSSession>(*this, is_client, alpns);
    }

    void GNUTLSCreds::set_client_tls_policy(
            gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        client_tls_policy.f = std::move(func);
        client_tls_policy.htype = htype;
        client_tls_policy.when = when;
        client_tls_policy.incoming = incoming;
    }

    void GNUTLSCreds::set_server_tls_policy(
            gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        server_tls_policy.f = std::move(func);
        server_tls_policy.htype = htype;
        server_tls_policy.when = when;
        server_tls_policy.incoming = incoming;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    void GNUTLSSession::set_tls_hook_functions()
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, gnutls_callback_wrapper);
    }

    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            bool is_client,
            const std::vector<std::string>& alpns,
            std::optional<gnutls_key> expected_key) :
            creds{creds}, is_client{is_client}, expected_remote_key{expected_key}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        auto direction_string = (is_client) ? "Client"s : "Server"s;
        log::trace(log_cat, "Creating {} GNUTLSSession", direction_string);

        uint32_t init_flags = is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;
        if (creds.using_raw_pk)
        {
            log::trace(log_cat, "Setting GNUTLS_ENABLE_RAWPK flag on gnutls_init");
            init_flags |= GNUTLS_ENABLE_RAWPK;
        }

        if (auto rv = gnutls_init(&session, init_flags); rv < 0)
        {
            log::error(log_cat, "{} gnutls_init failed: {}", direction_string, gnutls_strerror(rv));
            throw std::runtime_error("{} gnutls_init failed"_format(direction_string));
        }

        if (creds.using_raw_pk)
        {
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

        if (alpns.size())
        {
            std::vector<gnutls_datum_t> allowed_alpns;
            for (auto& s : alpns)
            {
                log::trace(log_cat, "GNUTLS adding \"{}\" to {} ALPNs", s, direction_string);
                allowed_alpns.emplace_back(gnutls_datum_t{
                        reinterpret_cast<uint8_t*>(const_cast<char*>(s.data())), static_cast<uint32_t>(s.size())});
            }

            if (auto rv =
                        gnutls_alpn_set_protocols(session, &(allowed_alpns[0]), allowed_alpns.size(), GNUTLS_ALPN_MANDATORY);
                rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }
        }
        else  // set default, mandatory ALPN string
        {
            if (auto rv = gnutls_alpn_set_protocols(session, &gnutls_default_alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }
        }

        if (creds.using_raw_pk)
        {
            // server always requests cert from client in raw public key mode
            if (not is_client)
            {
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
            }
        }

        if (is_client)
        {
            log::trace(log_cat, "gnutls configuring client session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }
        else
        {
            log::trace(log_cat, "gnutls configuring server session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds.cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_credentials_set failed");
        }

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (is_client)
        {
            if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            {
                log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_server_name_set failed");
            }
        }

        set_tls_hook_functions();
    }

    std::string_view GNUTLSSession::selected_alpn()
    {
        gnutls_datum_t proto;
        if (auto rv = gnutls_alpn_get_selected_protocol(session, &proto); rv < 0)
        {
            auto err = fmt::format("{} called, but ALPN negotiation incomplete.", __PRETTY_FUNCTION__);
            throw std::logic_error(err);
        }

        return proto.size ? std::string_view{(const char*)proto.data, proto.size} : ""sv;
    }

    int GNUTLSSession::do_tls_callback(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& policy = (is_client) ? creds.client_tls_policy : creds.server_tls_policy;

        if (policy)
        {
            if (policy.htype == htype && policy.when == when && policy.incoming == incoming)
            {
                log::debug(log_cat, "Calling {} tls policy cb", (is_client) ? "client" : "server");
                return policy(session, htype, when, incoming, msg);
            }
        }
        return 0;
    }

    bool GNUTLSSession::validate_remote_key()
    {
        log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);

        gnutls_certificate_type_t cert_type;

        cert_type = gnutls_certificate_type_get2(session, GNUTLS_CTYPE_PEERS);
        uint32_t cert_list_size = 0;
        const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
        if (cert_list_size == 0)
        {
            log::error(log_cat, "{} called, but peers cert list is empty.", __PRETTY_FUNCTION__);
            return false;
        }

        // this function is only for raw pubkey mode, and should not be called otherwise
        if (cert_type != GNUTLS_CRT_RAWPK)
        {
            log::error(log_cat, "{} called, but remote cert type is not raw pubkey.", __PRETTY_FUNCTION__);
            return false;
        }

        if (cert_list_size != 1)
        {
            log::error(log_cat, "{} called, but peers cert list has more than one entry.", __PRETTY_FUNCTION__);
            return false;
        }

        auto* cert_data = cert_list[0].data;
        auto cert_size = cert_list[0].size;
        log::warning(
                log_cat,
                "Validating pubkey \"cert\" of len {}:\n\n{}\n\n",
                cert_size,
                oxenc::to_hex(cert_data, cert_data + cert_size));

        // pubkey comes as 12 bytes header + 32 bytes key
        std::copy(cert_data + 12, cert_data + 44, remote_key.data());

        auto alpn = selected_alpn();

        if (is_client and expected_remote_key)
        {
            if (remote_key != *expected_remote_key)
            {
                log::error(log_cat, "Outbound connection received wrong public key from other end!");
                return false;
            }
            log::trace(log_cat, "Outbound connection received expected public key from other end.");
        }
        else if ((not is_client) and creds.key_verify)
        {
            log::trace(log_cat, "{}: Calling key verify callback", __PRETTY_FUNCTION__);
            return creds.key_verify(remote_key, alpn);
        }

        log::trace(log_cat, "{} reached end, defaulting to return true", __PRETTY_FUNCTION__);

        return true;
    }

}  // namespace oxen::quic
