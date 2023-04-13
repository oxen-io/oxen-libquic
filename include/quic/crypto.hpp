#pragma once



namespace oxen::quic
{
    /// Private key material for self-signing TLS certs and other PK material (ex: KEM)
    class TLSCertPrivateKeys
    {

    };

    /// Pinned self-signed TLS cert addressible by pubkey and IP
    /// Fulfills TLSCert_t type constraint
    class Pinned_TLSCert
    {

    };
    
    /// Pinned CA signed certificate used to connect to a remote QUIC server addressible
    /// by common name
    /// Fulfills TLSCert_t type constraint
    class x509_TLSCert
    {

    };

	///	Manages all pinned TLS certificates and wraps system's root CA trust
    class TLSCertManager
    {

    };

	///	Templatized type constraints for passing certs to network classes
	template <typename T>
	constexpr bool is_valid_cert = false;
	template <>
	inline constexpr bool is_valid_cert<Pinned_TLSCert> = true;
	template <>
	inline constexpr bool is_valid_cert<x509_TLSCert> = true;

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
