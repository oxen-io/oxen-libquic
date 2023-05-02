#include "crypto.hpp"
#include "server.hpp"
#include "client.hpp"
#include "connection.hpp"

#include <gnutls/gnutls.h>
#include <stdexcept>


#define CHECK(x) \
    if (x != 0) \
        {fprintf(stderr, "Function call to %s failed\n", __func__); return -1;}

#define ALPN "libquic"


namespace oxen::quic
{
    extern "C"
    {
        int
        server_cb_wrapper(gnutls_session_t session, unsigned int htype, unsigned int when, unsigned int incoming, const gnutls_datum_t *ms)
        {
            auto conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            auto server = static_cast<Connection*>(conn_ref->user_data)->server();

            if (!server)
            {
                fprintf(stderr, "Error: server unsuccessfully retrieved from conn_ref->user_data->server()\n");
                return -1;
            }

            return server->context->server_cb(session, htype, when, incoming, ms);
        }

        int
        client_cb_wrapper(gnutls_session_t session, unsigned int htype, unsigned int when, unsigned int incoming, const gnutls_datum_t *ms)
        {
            auto conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            auto client = static_cast<Connection*>(conn_ref->user_data)->client();

            if (!client)
            {
                fprintf(stderr, "Error: client unsuccessfully retrieved from conn_ref->user_data->server()\n");
                return -1;
            }

            return client->context->client_cb(session, htype, when, incoming, ms);
        }

        int
        server_protocol_hook(gnutls_session_t session, unsigned int type, unsigned int when, unsigned int incoming, const gnutls_datum_t *msg)
        {
            assert(type == GNUTLS_HANDSHAKE_CLIENT_HELLO);
            assert(when == GNUTLS_HOOK_POST);
            assert(incoming != 0);

            gnutls_datum_t alpn;

            // confirm ALPN extension
            CHECK(gnutls_alpn_get_selected_protocol(session, &alpn));

            // set protocol
            gnutls_alpn_set_protocols(session, &alpn, 1, 0);

            return 0;
        }

        int
        client_hook(gnutls_session_t session, unsigned int type, unsigned int when, unsigned int incoming, const gnutls_datum_t *msg)
        {
            // currently no-op
            return 0;
        }
    }


    GNUTLSContext::~GNUTLSContext()
    {
        gnutls_certificate_free_credentials(cred);

        gnutls_deinit(session);
    }


    // The session pointer to the conn_ref struct needs to be done at Connection creation, so
    // conn_link will likely need to stay a separate function, especially for server connections
    // created in Server::accept_initial_connection
    int
    GNUTLSContext::conn_link(Connection &conn)
    {
        gnutls_session_set_ptr(session, &conn.conn_ref);

        ngtcp2_conn_set_tls_native_handle(conn, &session);

        return 0;
    }

    
    int
    GNUTLSContext::client_init(GNUTLSCert& cert)
    {
        CHECK(config_client_certs(cert));

        CHECK(gnutls_certificate_allocate_credentials(&cred));

        CHECK(gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA));

        CHECK(ngtcp2_crypto_gnutls_configure_client_session(session));

        CHECK(gnutls_priority_init(&priority, NULL, NULL));
        CHECK(gnutls_priority_set(session, priority));

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO, GNUTLS_HOOK_POST, client_hook);

        if (cert.client_cb)
            gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY, GNUTLS_HOOK_POST, client_cb_wrapper);

        CHECK(ngtcp2_crypto_gnutls_configure_client_session(session));

        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred));

        return 0;
    }


    int
    GNUTLSContext::server_init(GNUTLSCert& cert)
    {
        CHECK(config_server_certs(cert));

        CHECK(gnutls_certificate_allocate_credentials(&cred));

        CHECK(gnutls_init(&session, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA));

        CHECK(gnutls_priority_init(&priority, NULL, NULL));
        CHECK(gnutls_priority_set(session, priority));

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO, GNUTLS_HOOK_POST, server_protocol_hook);

        if (cert.server_cb)
            gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY, GNUTLS_HOOK_POST, server_cb_wrapper);
        
        CHECK(ngtcp2_crypto_gnutls_configure_server_session(session));

        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred));

        return 0;
    }


    int
    GNUTLSContext::config_server_certs(GNUTLSCert& cert)
    {
        if (!cert.remotecafile.empty())
            CHECK(gnutls_certificate_set_x509_trust_file(cred, cert.remotecafile.data(), cert.remoteca_type));

        CHECK(gnutls_certificate_set_x509_key_file(cred, cert.certfile.data(), cert.keyfile.data(), cert.key_type));

        return 0;
    }


    int
    GNUTLSContext::config_client_certs(GNUTLSCert& cert)
    {
        // remote CA file is passed, but not remote cert file
        if (!cert.remotecafile.empty() && cert.remotecert.empty())
        {
            CHECK(gnutls_certificate_set_x509_trust_file(cred, cert.remotecafile.data(), cert.remoteca_type))
        }
        // remote cert file is passed, but not remote CA file
        else if (cert.remotecafile.empty() && !cert.remotecert.empty())
        {
            CHECK(gnutls_certificate_set_x509_trust_file(cred, cert.remotecert.data(), cert.remotecert_type));
        }
        else
        {
            if (!cert.server_cb)
                throw std::invalid_argument("Error. Either the remote CA, remote cert, or cert verification callback must be passed");
        }

        if (!cert.keyfile.empty() && !cert.certfile.empty())
            CHECK(gnutls_certificate_set_x509_key_file(cred, cert.certfile.data(), cert.keyfile.data(), cert.key_type));

        return 0;
    }


    int
    GNUTLSContext::config_certs(std::string pkeyfile, std::string certfile, gnutls_x509_crt_fmt_t type)
    {
        CHECK(gnutls_certificate_set_x509_trust_file(cred, certfile.data(), type));

        //CHECK(gnutls_certificate_set_x509_key_file(cred, const char *certfile, const char *keyfile, gnutls_x509_crt_fmt_t type));

        return 0;
    }

}   // namespace oxen::quic
