#pragma once

#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <memory>
#include <type_traits>
#include <unordered_map>


namespace oxen::quic
{
    class Connection;

    enum GNUTLS_verification_scheme
    { NO_VERIFY = 0, CA_VERIFY = 1, CALLBACK = 2 };

	// Pure virtual TLSContext base class; Derived classes manage all pinned TLS certificates and 
    // wrap system's root CA trust
    struct TLSContext
    {
        ngtcp2_crypto_conn_ref conn_ref;
        gnutls_session_t session;
        virtual ~TLSContext() = default;
        virtual int 
        conn_link(Connection& conn) = 0;
    };


    // Pure virtual TLSCert base class
    struct TLSCert
    {
        virtual ~TLSCert() = default;
        virtual std::shared_ptr<TLSContext> into_context() && = 0;
    };


    // Pinned self-signed TLS cert addressible by pubkey and IP
    // Fulfills TLSCert_t type constraint
    struct Pinned_TLSCert : TLSCert
    {
        std::shared_ptr<TLSContext> into_context() && override;
    };
    

    // Pinned CA signed certificate used to connect to a remote QUIC server addressible
    // by common name
    // Fulfills TLSCert_t type constraint
    struct x509_TLSCert : TLSCert
    {
        std::shared_ptr<TLSContext> into_context() && override;
    };


    // Null certificate for unsecured connections
    struct NullCert : TLSCert
    { 
        std::shared_ptr<TLSContext> into_context() && override;
    };


    // GNUTlS specific TLS certificate
    struct GNUTLSCert : TLSCert
    {
        int type;
        std::string keyfile;
        std::string certfile;
        std::string remotecert;     // if client, this is server cert and vice versa
        std::string remotecafile;   // if client, this is server CA and vice versa
        gnutls_x509_crt_fmt_t key_type;
        gnutls_x509_crt_fmt_t cert_type;
        gnutls_x509_crt_fmt_t remotecert_type;
        gnutls_x509_crt_fmt_t remoteca_type;
        server_tls_callback_t server_tls_cb;
        client_tls_callback_t client_tls_cb;
        GNUTLS_verification_scheme scheme;

        // when called by server for no client verification
        explicit GNUTLSCert(std::string server_key, std::string server_cert) 
            : keyfile{server_key}, certfile{server_cert} 
        {
            fprintf(stderr, "GNUTLSCert constructor A\n");
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = NO_VERIFY;
        };

        // when called by server for client CA verification
        explicit GNUTLSCert(std::string server_key, std::string server_cert, std::string client_CA, int type = 1)
            : keyfile{server_key}, certfile{server_cert}, remotecafile{client_CA}
        {
            fprintf(stderr, "GNUTLSCert constructor B\n");
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            auto clientca_ext = str_tolower(std::filesystem::path(remotecafile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            remoteca_type = (clientca_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = CA_VERIFY;
        };

        // when called by server for client callback verification
        explicit GNUTLSCert(std::string server_key, std::string server_cert, server_tls_callback_t server_callback)
            : keyfile{server_key}, certfile{server_cert}, server_tls_cb{server_callback} 
        {
            fprintf(stderr, "GNUTLSCert constructor C\n");
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = CALLBACK;
        };

        // when called by client
        explicit GNUTLSCert(
            int type = 0,
            std::string client_key = "", 
            std::string client_cert = "", 
            std::string server_cert = "", 
            std::string server_CA = "", 
            client_tls_callback_t client_cb = nullptr) : 
            keyfile{client_key}, 
            certfile{client_cert}, 
            remotecert{server_cert}, 
            remotecafile{server_CA},
            client_tls_cb{client_cb}
        {
            fprintf(stderr, "GNUTLSCert constructor D\n");
            if (!keyfile.empty())
            {
                auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
                key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            if (!certfile.empty())
            {
                auto cert_ext = str_tolower(std::filesystem::path(keyfile).extension());
                cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            if (!remotecert.empty())
            {
                auto remote_ext = str_tolower(std::filesystem::path(keyfile).extension());
                remotecert_type = (remote_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            if (!remotecafile.empty())
            {
                auto remoteca_ext = str_tolower(std::filesystem::path(keyfile).extension());
                remoteca_type = (remoteca_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            
            if (client_cb)
                scheme = CALLBACK;
            else if (remotecert_type || remoteca_type)
                scheme = CA_VERIFY;
            else
                scheme = CALLBACK;
        };

        //std::shared_ptr<TLSContext>
        //into_context() && override;
    };


    namespace opt
    {
        struct remote_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct local_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct server_tls : public GNUTLSCert 
        { 
            using GNUTLSCert::GNUTLSCert; 
            std::shared_ptr<TLSContext>
            into_context() && override;
        };
        struct client_tls : public GNUTLSCert 
        { 
            using GNUTLSCert::GNUTLSCert; 
            std::shared_ptr<TLSContext>
            into_context() && override;
        };
    }   // namespace oxen::quic::opt


    // GnuTLS certificate context
    struct GNUTLSContext : TLSContext
    {
        /*
        explicit GNUTLSContext(GNUTLSCert cert) 
        {
            fprintf(stderr, "GNUTLSContext constructor A\n");
            if (cert.system)
                client_sysinit();
        };
        */

        template <typename T, std::enable_if_t<std::is_same_v<T, opt::server_tls>, bool> = true>
        explicit GNUTLSContext(T& cert)
        {
            fprintf(stderr, "GNUTLSContext constructor A\n");
            if (cert.server_tls_cb)
                server_tls_cb = std::move(cert.server_tls_cb);
            server_init(cert);
        };

        template <typename T, std::enable_if_t<std::is_same_v<T, opt::client_tls>, bool> = true>
        explicit GNUTLSContext(T& cert)
        {
            fprintf(stderr, "GNUTLSContext constructor B\n");
            if (cert.client_tls_cb)
                client_tls_cb = std::move(cert.client_tls_cb);
            client_init(cert);
        };

        ~GNUTLSContext();

        gnutls_certificate_credentials_t cred;
        gnutls_priority_t priority;
        gnutls_x509_crt_int* cert;
        // gnutls_session_t session;
        server_tls_callback_t server_tls_cb;
        client_tls_callback_t client_tls_cb;
        
        int
        client_init(GNUTLSCert& cert);

        int
        server_init(GNUTLSCert& cert);

        int
        conn_link(Connection& conn);

      private:
        int
        config_server_certs(GNUTLSCert& cert);
        int
        config_client_certs(GNUTLSCert& cert);

    };


    // Null certificate context
    struct NullContext : TLSContext
    {
        explicit NullContext(NullCert ncert) : cert{ncert} {};

        NullCert cert;
    };


    // X509 certificate context
    struct x509_Context : TLSContext
    {
        explicit x509_Context(x509_TLSCert xcert) : cert{xcert} {};

        x509_TLSCert cert;
    };


    // Private key material for self-signing TLS certs and other PK material (ex: KEM)
    struct TLSCertPrivateKeys
    {
        // 
    };


    // Provides TLS validation hook for handshake in either peer or server role
    template <typename TLSCert_t, std::enable_if_t<std::is_base_of_v<TLSCert, TLSCert_t>, bool> = true>
    class TLSValidator
    {
        public:
            explicit TLSValidator(TLSCert_t&& t) : cert{t} {};

        private:
            TLSCert_t cert;
            
    };

    /*
    inline std::unique_ptr<TLSContext>
    GNUTLSCert::into_context() &&
    {
        return std::make_unique<GNUTLSContext>(*this);
    }
    */

    inline std::shared_ptr<TLSContext>
    opt::server_tls::into_context() &&
    {
        return std::make_shared<GNUTLSContext>(*this);
    }

    inline std::shared_ptr<TLSContext>
    opt::client_tls::into_context() &&
    {
        return std::make_shared<GNUTLSContext>(*this);
    }


    extern "C"
    {
        int 
        server_cb_wrapper(
            gnutls_session_t session, unsigned int htype, unsigned int when, unsigned int incoming, const gnutls_datum_t* ms);
        int
        client_cb_wrapper(
            gnutls_session_t session, unsigned int htype, unsigned int when, unsigned int incoming, const gnutls_datum_t *ms);
        int
        server_protocol_hook(
            gnutls_session_t session, unsigned int type, unsigned int when, unsigned int incoming, const gnutls_datum_t *msg);
    }

}   // namespace oxen::quic
