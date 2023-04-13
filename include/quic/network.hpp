#pragma once

#include "crypto.hpp"

#include <assert.h>
#include <cstddef>
#include <type_traits>


namespace oxen::quic
{
    /// Handles packet I/O between remote NetworkEndpoints from one or more local NetworkEndpoint(s)
    class NetworkIO
    {

    };


    /// takes in a TLSCert and fetches asynchronously a set of NetworkEndpoints in preferred order which 
    /// we can use to attempt to establish a connection with
    /// TLSCert_t must fufill type constraint
    template <typename TLSCert_t, std::enable_if_t<is_valid_cert<TLSCert_t>, bool> = true>
    class NetworkEndpointResolver
    {
        public:
            explicit NetworkEndpointResolver(TLSCert_t&& t) : cert{t} {};

        private:
            TLSCert_t cert;
    };

    /// Provides TLS validation hook for handshake in either peer or server role
    /// TLSCert_t must fufill the TLSCert type constraint
    template <typename TLSCert_t, std::enable_if_t<is_valid_cert<TLSCert_t>, bool> = true>
    class TLSValidator
    {
        public:
            explicit TLSValidator(TLSCert_t&& t) : cert{t} {};

        private:
            TLSCert_t cert;
    };



}   // namespace oxen::quic
