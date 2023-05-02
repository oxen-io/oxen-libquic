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
        virtual ~TLSContext() = default;
    };


    // Pure virtual TLSCert base class
    struct TLSCert
    {
        virtual ~TLSCert() = default;
        virtual std::unique_ptr<TLSContext> into_context() && = 0;
    };


    // Pinned self-signed TLS cert addressible by pubkey and IP
    // Fulfills TLSCert_t type constraint
    struct Pinned_TLSCert : TLSCert
    {
        std::unique_ptr<TLSContext> into_context() && override;
    };
    

    // Pinned CA signed certificate used to connect to a remote QUIC server addressible
    // by common name
    // Fulfills TLSCert_t type constraint
    struct x509_TLSCert : TLSCert
    {
        std::unique_ptr<TLSContext> into_context() && override;
    };


    // Null certificate for unsecured connections
    struct NullCert : TLSCert
    { 
        std::unique_ptr<TLSContext> into_context() && override;
    };


    // GNUTlS specific TLS certificate
    struct GNUTLSCert : TLSCert
    {
        std::string keyfile;
        std::string certfile;
        std::string remotecert;     // if client, this is server cert and vice versa
        std::string remotecafile;   // if client, this is server CA and vice versa
        gnutls_x509_crt_fmt_t key_type;
        gnutls_x509_crt_fmt_t cert_type;
        gnutls_x509_crt_fmt_t remotecert_type;
        gnutls_x509_crt_fmt_t remoteca_type;
        server_callback server_cb;
        client_callback client_cb;
        GNUTLS_verification_scheme scheme;

        // when called by server: no client verification
        explicit GNUTLSCert(std::string key, std::string cert) 
            : keyfile{key}, certfile{cert} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = NO_VERIFY;
        };

        // when called by server: client CA verification
        explicit GNUTLSCert(std::string key, std::string cert, std::string client_CA)
            : keyfile{key}, certfile{cert}, remotecafile{client_CA} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            auto clientca_ext = str_tolower(std::filesystem::path(remotecafile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            remoteca_type = (clientca_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = CA_VERIFY;
        };

        // when called by server: client callback verification
        explicit GNUTLSCert(std::string key, std::string cert, server_callback server_callback)
            : keyfile{key}, certfile{cert}, server_cb{server_callback} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = (key_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = (cert_ext == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            scheme = CALLBACK;
        };

        // when called by client
        explicit GNUTLSCert(
            std::string client_key = "", 
            std::string client_cert = "", 
            std::string server_cert = "", 
            std::string server_CA = "", 
            client_callback client_cb = nullptr) : 
            keyfile{client_key}, 
            certfile{client_cert}, 
            remotecert{server_cert}, 
            remotecafile{server_cert},
            client_cb{client_cb}
        {
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

        std::unique_ptr<TLSContext>
        into_context() && override;
    };


    namespace opt
    {
        struct remote_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct local_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct server_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct client_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
    }   // namespace oxen::quic::opt


    // GnuTLS certificate context
    struct GNUTLSContext : TLSContext
    {
        explicit GNUTLSContext(GNUTLSCert cert);

        template <typename T, std::enable_if_t<std::is_same_v<T, opt::server_tls>, bool> = true>
        explicit GNUTLSContext(T* cert)
        {
            if (cert->server_cb)
                server_cb = std::move(cert->server_cb);

            server_init(cert);
        };

        template <typename T, std::enable_if_t<std::is_same_v<T, opt::client_tls>, bool> = true>
        explicit GNUTLSContext(T* cert)
        {
            if (cert->client_cb)
                client_cb = std::move(cert->client_cb);

            client_init(cert);
        };

        ~GNUTLSContext();

        gnutls_certificate_credentials_t cred;
        gnutls_priority_t priority;
        gnutls_x509_crt_int* cert;
        gnutls_session_t session;
        server_callback server_cb;
        client_callback client_cb;
        
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
        int
        config_certs(std::string pkeyfile, std::string certfile, gnutls_x509_crt_fmt_t type);

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


    inline std::unique_ptr<TLSContext>
    GNUTLSCert::into_context() &&
    {
        return std::make_unique<GNUTLSContext>(std::move(*this));
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
