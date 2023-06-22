#include "crypto.hpp"

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
}

#include <stdexcept>

#include "client.hpp"
#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "server.hpp"

namespace oxen::quic
{
    extern "C"
    {
        int gnutls_callback_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& conn = static_cast<Connection*>(conn_ref->user_data);
            const GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->tls_session.get());
            assert(tls_session);

            return tls_session->do_tls_callback(session, htype, when, incoming, msg);
        }
    }

    GNUTLSCreds::GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg)
    {
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
            log::warning(log_cat, "Server gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        if (ca)
        {
            if (auto rv = (ca.from_mem) ? gnutls_certificate_set_x509_trust_mem(cred, ca, ca)
                                        : gnutls_certificate_set_x509_trust_file(cred, ca, ca);
                rv < 0)
            {
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
                throw std::invalid_argument("gnutls didn't like a specified trust file/memblock");
            }
        }

        if (auto rv = (lcert.from_mem) ? gnutls_certificate_set_x509_key_mem(cred, lcert, lkey, lkey)
                                       : gnutls_certificate_set_x509_key_file(cred, lcert, lkey, lkey);
            rv < 0)
        {
            log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
            throw std::invalid_argument("gnutls didn't like a specified key file/memblock");
        }

        log::info(log_cat, "Completed credential initialization");
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::warning(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_certificate_free_credentials(cred);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make(
            std::string remote_key, std::string remote_cert, std::string local_cert, std::string ca)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(remote_key, remote_cert, local_cert, ca)};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(const ngtcp2_crypto_conn_ref& conn_ref, bool is_client)
    {
        return std::make_unique<GNUTLSSession>(*this, conn_ref, is_client);
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::warning(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    void GNUTLSSession::set_tls_hook_functions()
    {
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, gnutls_callback_wrapper);
    }

    GNUTLSSession::GNUTLSSession(GNUTLSCreds& creds, const ngtcp2_crypto_conn_ref& conn_ref_, bool is_client) :
            TLSSession{conn_ref_}, creds{creds}, is_client{is_client}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        if (auto rv = gnutls_init(&session, is_client ? GNUTLS_CLIENT : GNUTLS_SERVER); rv < 0)
        {
            log::warning(log_cat, "Server gnutls_init failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("Server gnutls_init failed");
        }

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
        {
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_set_default_priority failed");
        }

        if (is_client)
        {
            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }
        else
        {
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
        if (is_client && creds.client_tls_policy)
            return creds.client_tls_policy(session, htype, when, incoming, msg);
        else if ((not is_client) && creds.server_tls_policy)
            return creds.server_tls_policy(session, htype, when, incoming, msg);

        return 0;
    }

}  // namespace oxen::quic
