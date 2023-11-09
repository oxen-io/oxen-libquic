#include "gnutls_crypto.hpp"

namespace oxen::quic
{
    extern "C"
    {
        int cert_verify_callback_gnutls(gnutls_session_t g_session)
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            auto* tls_session = get_session_from_gnutls(g_session);
            assert(tls_session->get_session() == g_session);

            // 0 is pass, negative is fail
            return tls_session->validate_remote_key() ? 0 : -1;
        }
    }

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

}  // namespace oxen::quic
