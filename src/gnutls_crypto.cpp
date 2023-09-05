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
    const auto client_alpn = "lokinet_client"s;
    const auto relay_alpn = "lokinet_relay"s;

    const gnutls_datum_t alpns[] = {
            {.data = (uint8_t*)client_alpn.c_str(), .size = 14}, {.data = (uint8_t*)relay_alpn.c_str(), .size = 13}};

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

    GNUTLSCreds::GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg)
    {
        if (local_key.empty() || local_cert.empty())
            throw std::runtime_error{
                    "Must initialize GNUTLS credentials using local private key and certificate at minimum"};

        datum lkey = datum{local_key};
        datum lcert = datum{local_cert};
        datum rcert;
        if (not remote_cert.empty())
            rcert = datum{remote_cert};
        datum ca;
        if (not ca_arg.empty())
            ca = datum{ca};

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        if (ca)
        {
            if (auto rv = (ca.from_mem)
                                ? gnutls_certificate_set_x509_trust_mem(cred, ca, ca.format)
                                : gnutls_certificate_set_x509_trust_file(cred, ca.path.u8string().c_str(), ca.format);
                rv < 0)
            {
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
                throw std::invalid_argument("gnutls didn't like a specified trust file/memblock");
            }
        }

        if (auto rv = (lcert.from_mem)
                            ? gnutls_certificate_set_x509_key_mem(cred, lcert, lkey, lkey.format)
                            : gnutls_certificate_set_x509_key_file(
                                      cred, lcert.path.u8string().c_str(), lkey.path.u8string().c_str(), lkey.format);
            rv < 0)
        {
            log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
            throw std::invalid_argument("gnutls didn't like a specified key file/memblock");
        }

        log::info(log_cat, "Completed credential initialization");
    }

    GNUTLSCreds::GNUTLSCreds(std::string ed_seed, std::string ed_pubkey, bool snode) : using_raw_pk{true}, is_snode{snode}
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");

        // These bytes mean "this is a raw Ed25519 private key" in ASN.1 (or something like that)
        auto asn_seed_bytes = oxenc::from_hex("302e020100300506032b657004220420");
        asn_seed_bytes += ed_seed;

        std::string seed_pem = "-----BEGIN PRIVATE KEY-----\n";
        seed_pem += oxenc::to_base64(asn_seed_bytes);
        seed_pem += "\n-----END PRIVATE KEY-----\n";

        // These bytes mean "this is a raw Ed25519 public key" in ASN.1 (or something like that)
        auto asn_pubkey_bytes = oxenc::from_hex("302a300506032b6570032100");
        asn_pubkey_bytes += ed_pubkey;

        std::string pubkey_pem = "-----BEGIN PUBLIC KEY-----\n";
        pubkey_pem += oxenc::to_base64(asn_pubkey_bytes);
        pubkey_pem += "\n-----END PUBLIC KEY-----\n";

        // uint32_t cast to appease narrowing conversion gods
        const gnutls_datum_t seed_datum{(uint8_t*)seed_pem.c_str(), (uint32_t)seed_pem.size()};
        const gnutls_datum_t pubkey_datum{(uint8_t*)pubkey_pem.c_str(), (uint32_t)pubkey_pem.size()};

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
                    cred, &pubkey_datum, &seed_datum, GNUTLS_X509_FMT_PEM, nullptr, usage_flags, nullptr, 0, 0);
            rv < 0)
        {
            log::warning(log_cat, "gnutls import of raw Ed keys failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls import of raw Ed keys failed");
        }

        constexpr auto* priority =
                "NORMAL:+ECDHE-PSK:+PSK:+ECDHE-ECDSA:+AES-128-CCM-8:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL:+"
                "SHA256";
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

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string seed, std::string pubkey, bool is_relay)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(seed, pubkey, is_relay)};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(bool is_client)
    {
        return std::make_unique<GNUTLSSession>(*this, is_client);
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

    GNUTLSSession::GNUTLSSession(GNUTLSCreds& creds, bool is_client, std::optional<gnutls_key> expected_key) :
            creds{creds}, is_client{is_client}, expected_remote_key{expected_key}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        log::trace(log_cat, "Creating {} GNUTLSSession", (is_client) ? "client" : "server");

        uint32_t init_flags = is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;
        if (creds.using_raw_pk)
        {
            log::trace(log_cat, "Setting GNUTLS_ENABLE_RAWPK flag on gnutls_init");
            init_flags |= GNUTLS_ENABLE_RAWPK;
        }

        if (auto rv = gnutls_init(&session, init_flags); rv < 0)
        {
            auto s = (is_client) ? "Client"s : "Server"s;
            log::error(log_cat, "{} gnutls_init failed: {}", s, gnutls_strerror(rv));
            throw std::runtime_error("{} gnutls_init failed"_format(s));
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

        if (creds.using_raw_pk)
        {
            // server needs to accept either alpn, "client (ngtcp2)" can be lokinet client or relay
            // and must send only that alpn
            const auto* proto = &alpns[0];
            bool both = false;
            if (creds.is_snode)
            {
                both = is_client ? false : true;  // allow both alpns, if snode "relay"
                if (not both)
                    proto = &alpns[1];  // only send relay alpn, if snode "client"
            }
            else if (not is_client)
            {
                log::error(log_cat, "inbound connection on non-snode, this is invalid");
                throw std::runtime_error("inbound connection on non-snode, this is invalid");
            }

            if (auto rv = gnutls_alpn_set_protocols(session, proto, both ? 2 : 1, 0); rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }

            // server always requests cert from client; in future can try to parse client alpn offering here
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

        gnutls_datum_t proto;
        if (auto rv = gnutls_alpn_get_selected_protocol(session, &proto); rv < 0)
        {
            log::error(log_cat, "{} called, but ALPN negotiation incomplete.", __PRETTY_FUNCTION__);
            return false;
        }

        if (is_client)
        {
            remote_is_relay = true;
        }
        else
        {
            std::string_view proto_sv{(const char*)proto.data, proto.size};
            if (proto_sv == client_alpn)
                remote_is_relay = false;
            else if (proto_sv == relay_alpn)
                remote_is_relay = true;
            else
            {
                log::error(log_cat, "Remote ALPN is invalid, how did we get here??", __PRETTY_FUNCTION__);
                throw std::logic_error{
                        "GNUTLSSession::validate_remote_key session validating keys but ALPN negotiation broke."};
            }
        }

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
            return creds.key_verify(remote_key, remote_is_relay);
        }

        log::trace(log_cat, "{} reached end, defaulting to return true", __PRETTY_FUNCTION__);

        return true;
    }

}  // namespace oxen::quic
