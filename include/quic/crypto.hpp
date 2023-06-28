#pragma once

extern "C"
{
#include <ngtcp2/ngtcp2_crypto.h>
}

#include <memory>

#include "utils.hpp"

namespace oxen::quic
{
    class TLSSession;

    class TLSCreds
    {
      public:
        virtual std::unique_ptr<TLSSession> make_session(const ngtcp2_crypto_conn_ref& conn_ref, bool is_client) = 0;
    };

    class TLSSession
    {
      protected:
        ngtcp2_crypto_conn_ref conn_ref;
        TLSSession(const ngtcp2_crypto_conn_ref& conn_ref) : conn_ref{conn_ref} {}

      public:
        virtual void* get_session() = 0;
        virtual ~TLSSession() { log::trace(log_cat, "{} called", __PRETTY_FUNCTION__); }
    };

}  // namespace oxen::quic
