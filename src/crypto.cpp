#include "crypto.hpp"
#include "connection.hpp"

#include <gnutls/gnutls.h>


#define CHECK(x) \
    if (x != 0) \
        {fprintf(stderr, "Function call to %s failed\n", __func__); return -1;}

#define ALPN "libquic"


namespace oxen::quic
{
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


    GNUTLSContext::GNUTLSContext(GNUTLSCert cert)
    {
        // by the time the constructor is called, the templated GNUTLSCert constructors have stored all necessary information
        if (cert.server_cb)
        {
            server_cb = std::move(cert.server_cb);
        }
        
    }


    GNUTLSContext::~GNUTLSContext()
    {
        gnutls_certificate_free_credentials(cred);

        gnutls_deinit(session);
    }


    //  TODO: figure out a logical way to order these function calls. The main differences
    //  between server and client initialization are:
    //      - GNUTLS_{CLIENT/SERVER} Is passed as a flag to gnutls_init
    //          - this is stored in session; ngtcp2_crypto_gnutls_config_{client/server}_session
    //            call the same underlying function
    //      - server needs to set a certificate key pair as well
    //      - server can set protocol during handshake after client hello by calling
    //        gnutls_alpn_get_selected protocol (see /ngtcp2/examples/tls_server_session.cc)
    //      
    //  The session pointer to the conn_ref struct needs to be done at Connection creation, so
    //  conn_link will likely need to stay a separate function
    int
    GNUTLSContext::conn_link(Connection &conn)
    {
        gnutls_session_set_ptr(session, &conn.conn_ref);

        ngtcp2_conn_set_tls_native_handle(conn, &session);

        return 0;
    }

    
    int
    GNUTLSContext::client_init(std::string pkeyfile, gnutls_x509_crt_fmt_t type)
    {
        //CHECK(config_certs(pkeyfile, type));
        CHECK(gnutls_certificate_allocate_credentials(&cred));

        CHECK(gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA));

        CHECK(ngtcp2_crypto_gnutls_configure_client_session(session));

        CHECK(gnutls_priority_init(&priority, NULL, NULL));
        CHECK(gnutls_priority_set(session, priority));

        gnutls_handshake_set_hook_function(
            session, GNUTLS_HANDSHAKE_CLIENT_HELLO, GNUTLS_HOOK_POST, client_hook);

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

        gnutls_handshake_set_hook_function(
            session, GNUTLS_HANDSHAKE_CLIENT_HELLO, GNUTLS_HOOK_POST, server_protocol_hook);

        CHECK(ngtcp2_crypto_gnutls_configure_server_session(session));

        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred));

        return 0;
    }


    int
    GNUTLSContext::config_server_certs(GNUTLSCert& cert)
    {
        CHECK(gnutls_certificate_set_x509_trust_file(cred, cert.certfile.data(), cert.cert_type));

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
