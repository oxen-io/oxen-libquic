#pragma once

#include "utils.hpp"

#include <gnutls/crypto.h>

#include <memory>
#include <unordered_map>

namespace oxen::quic
{
    class Connection;

    // Cert base class
    struct TLSCert
    {
        virtual ~TLSCert() = default;
    };

    //  Pinned self-signed TLS cert addressible by pubkey and IP
    //  Fulfills TLSCert_t type constraint
    struct Pinned_TLSCert : public TLSCert
    {
        //
    };
    
    //  Pinned CA signed certificate used to connect to a remote QUIC server addressible
    //  by common name
    //  Fulfills TLSCert_t type constraint
    struct x509_TLSCert : public TLSCert
    {
        //
    };

    //  Null cert for unsecured connections
    struct NullCert : public TLSCert
    { 
        //
    };

    //  Private key material for self-signing TLS certs and other PK material (ex: KEM)
    struct TLSCertPrivateKeys
    {
        //
    };

	// 	Manages all pinned TLS certificates and wraps system's root CA trust
    struct TLSCertManager
    {
        std::unique_ptr<TLSCert> cert{};
        gnutls_certificate_credentials_t cred;

        int
        gnutls_config(Connection& c);
    };

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
