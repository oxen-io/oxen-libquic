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

#define CHECK(x)                                                     \
    if (x < 0)                                                       \
    {                                                                \
        log::trace(log_cat, "Function call to {} failed", __func__); \
    }

#define ALPN "h2"

namespace oxen::quic
{
    static const gnutls_datum_t alpn = {(uint8_t*)ALPN, sizeof(ALPN) - 1};

    extern "C"
    {
        int server_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* ms)
        {
            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& server = static_cast<Connection*>(conn_ref->user_data)->server();

            if (!server)
            {
                log::warning(log_cat, "Error: server unsuccessfully retrieved from conn_ref->user_data->server()");
                return -1;
            }

            return server->context->server_tls_cb(session, htype, when, incoming, ms);
        }

        int client_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& client = static_cast<Connection*>(conn_ref->user_data)->client();

            if (!client)
            {
                log::warning(log_cat, "Error: client unsuccessfully retrieved from conn_ref->user_data->client()");
                return -1;
            }

            auto gtls_ctx = std::dynamic_pointer_cast<GNUTLSContext>(client->context->tls_ctx);

            return gtls_ctx->client_tls_cb(session, htype, when, incoming, msg);
        }

        int server_protocol_hook(
                gnutls_session_t session,
                unsigned int type,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            assert(type == GNUTLS_HANDSHAKE_CLIENT_HELLO);
            assert(when == GNUTLS_HOOK_POST);
            assert(incoming != 0);

            gnutls_datum_t _alpn;

            // confirm ALPN extension
            CHECK(gnutls_alpn_get_selected_protocol(session, &_alpn));

            // set protocol
            CHECK(gnutls_alpn_set_protocols(session, &_alpn, 1, 0));

            return 0;
        }

        int client_verification_hook(
                gnutls_session_t session,
                unsigned int type,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return 0;
        }
    }

    GNUTLSCert::GNUTLSCert(opt::client_tls client_tls) :
            private_key{client_tls.private_key},
            local_cert{client_tls.local_cert},
            scheme{client_tls.scheme},
            cred{client_tls.cred}
    {
        log::trace(log_cat, "GNUTLSCert direct construction from opt::client_tls");
        if (client_tls.remote_cert)
            remote_cert = client_tls.remote_cert;
        if (client_tls.remote_ca)
            remote_ca = client_tls.remote_ca;
    }

    GNUTLSCert::GNUTLSCert(opt::server_tls server_tls) :
            private_key{server_tls.private_key},
            local_cert{server_tls.local_cert},
            scheme{server_tls.scheme},
            cred{server_tls.cred}
    {
        log::trace(log_cat, "GNUTLSCert direct construction from opt::server_tls");
        if (server_tls.remote_cert)
            remote_cert = server_tls.remote_cert;
        if (server_tls.remote_ca)
            remote_ca = server_tls.remote_ca;
    }

    std::shared_ptr<TLSContext> GNUTLSCert::GNUTLSCert::into_context() &&
    {
        return std::make_unique<GNUTLSContext>(*this);
    }

    int GNUTLSCert::_client_cred_init()
    {
        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
            log::warning(log_cat, "Server gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_certificate_set_x509_system_trust(cred); rv < 0)
            log::warning(log_cat, "Set x509 system trust failed with code {}", gnutls_strerror(rv));

        // remote CA file is passed, but not remote cert file
        if (remote_ca && !remote_cert)
        {
            if (auto rv = (remote_ca.from_mem) ? gnutls_certificate_set_x509_trust_mem(cred, remote_ca, remote_ca)
                                               : gnutls_certificate_set_x509_trust_file(cred, remote_ca, remote_ca);
                rv < 0)
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
        }
        // remote cert file is passed, but not remote CA file
        else if (!remote_ca && remote_cert)
        {
            if (auto rv = (remote_cert.from_mem) ? gnutls_certificate_set_x509_trust_mem(cred, remote_cert, remote_cert)
                                                 : gnutls_certificate_set_x509_trust_file(cred, remote_cert, remote_cert);
                rv < 0)
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
        }
        else
        {
            if (!server_tls_cb)
                throw std::invalid_argument(
                        "Error. Either the remote CA, remote cert, or cert verification callback must be passed");
        }

        if (private_key && local_cert)
        {
            if (auto rv = (local_cert.from_mem)
                                ? gnutls_certificate_set_x509_key_mem(cred, local_cert, private_key, private_key)
                                : gnutls_certificate_set_x509_key_file(cred, local_cert, private_key, private_key);
                rv < 0)
                log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
        }

        log::info(log_cat, "Completed client credential initialization");
        return 0;
    }

    int GNUTLSCert::_server_cred_init()
    {
        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
            log::warning(log_cat, "Server gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_certificate_set_x509_system_trust(cred); rv < 0)
            log::warning(log_cat, "Set x509 system trust failed with code {}", gnutls_strerror(rv));

        if (remote_ca)
        {
            if (auto rv = (remote_ca.from_mem) ? gnutls_certificate_set_x509_trust_mem(cred, remote_ca, remote_ca)
                                               : gnutls_certificate_set_x509_trust_file(cred, remote_ca, remote_ca);
                rv < 0)
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
        }

        if (auto rv = (local_cert.from_mem)
                            ? gnutls_certificate_set_x509_key_mem(cred, local_cert, private_key, private_key)
                            : gnutls_certificate_set_x509_key_file(cred, local_cert, private_key, private_key);
            rv < 0)
            log::warning(log_cat, "Set x509 key with code {}", gnutls_strerror(rv));

        log::info(log_cat, "Completed server credential initialization");
        return 0;
    }

    GNUTLSContext::~GNUTLSContext()
    {
        gnutls_certificate_free_credentials(gcert.cred);

        gnutls_deinit(session);
    }

    int GNUTLSContext::_server_session_init()
    {
        if (auto rv = gnutls_init(&session, GNUTLS_SERVER); rv < 0)
            log::warning(log_cat, "Server gnutls_init failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));

        if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, gcert.cred); rv < 0)
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            log::warning(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));

        log::info(log_cat, "Completed server session initialization");
        return 0;
    }

    int GNUTLSContext::_client_session_init()
    {
        if (auto rv = gnutls_init(&session, GNUTLS_CLIENT); rv < 0)
            log::warning(log_cat, "Client gnutls_init failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));

        if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, gcert.cred); rv < 0)
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            log::warning(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));

        log::info(log_cat, "Completed client_init");

        return 0;
    }

    // Note: set_hook_function is purposely not wrapped in a conditional checking 'if (client_tls_cb)' inside
    // _{client, server}_session_init(). If the server/client tls callbacks are passed to client_connect or
    // server_listen prior to the tls information, it will set a nullptr for the callback function. This is no
    // good. By separating the callback emplacement, we ensure that it is called when the tls callback is processed
    void GNUTLSContext::client_callback_init()
    {
        log::debug(log_cat, "Emplacing client tls callback in hook function...");
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, client_cb_wrapper);
    }

    void GNUTLSContext::server_callback_init()
    {
        log::debug(log_cat, "Emplacing server tls callback in hook function...");
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, server_cb_wrapper);
    }
}  // namespace oxen::quic
