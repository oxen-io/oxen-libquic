#pragma once

#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <memory>
#include <unordered_map>


namespace oxen::quic
{
    class Connection;

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
        std::string clientcafile;
        gnutls_x509_crt_fmt_t key_type;
        gnutls_x509_crt_fmt_t cert_type;
        gnutls_x509_crt_fmt_t cca_type;
        server_callback server_cb;

        // when called by server: no client verification
        explicit GNUTLSCert(std::string key, std::string cert) 
            : keyfile{key}, certfile{cert} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = key_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = cert_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
        };

        // when called by server: client CA verification
        explicit GNUTLSCert(std::string key, std::string cert, std::string client_CA)
            : keyfile{key}, certfile{cert}, clientcafile{client_CA} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            auto clientca_ext = str_tolower(std::filesystem::path(clientcafile).extension());
            key_type = key_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = cert_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cca_type = clientca_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
        };

        // when called by server: client callback verification
        explicit GNUTLSCert(std::string key, std::string cert, server_callback server_callback)
            : keyfile{key}, certfile{cert}, server_cb{server_callback} 
        {
            auto key_ext = str_tolower(std::filesystem::path(keyfile).extension());
            auto cert_ext = str_tolower(std::filesystem::path(certfile).extension());
            key_type = key_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            cert_type = cert_ext == ".pem" ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
        };

        std::unique_ptr<TLSContext>
        into_context() && override;
    };


    // GnuTLS certificate context
    struct GNUTLSContext : TLSContext
    {
        explicit GNUTLSContext(GNUTLSCert cert);
        ~GNUTLSContext();

        gnutls_certificate_credentials_t cred;
        gnutls_priority_t priority;
        gnutls_x509_crt_int* cert;
        gnutls_session_t session;
        server_callback server_cb;
        
        int
        client_init(std::string pkeyfile, gnutls_x509_crt_fmt_t type);

        int
        server_init(GNUTLSCert& cert);

        int
        conn_link(Connection& conn);

      private:
        int
        config_server_certs(GNUTLSCert& cert);
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


    namespace opt
    {
        struct remote_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct local_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
        struct server_tls : public GNUTLSCert { using GNUTLSCert::GNUTLSCert; };
    }   // namespace oxen::quic::opt

}   // namespace oxen::quic


/*
    TODO:
      - Currently, 'ngtcp2_crypto_gnutls_configure_client_session' and 'ngtcp2_crypto_gnutls_configure_server_session'
        are called in Connection::init_gnutls to set up the TLS keys and secrets for the client and server connection
        objects. If we want to implement the capability to provide a custom encryption suite (or none in the case of 
        NullCrypto), modifications need to be made to the Connection class functions to properly set up keys/secrets/etc.

      - Currently, no event loop logic is yet implemented.

      - 

*/
