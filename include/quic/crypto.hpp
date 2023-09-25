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
        virtual std::unique_ptr<TLSSession> make_session(bool is_client, const std::vector<std::string>& alpns) = 0;
        virtual ~TLSCreds() = default;
    };

    class TLSSession
    {
      public:
        ngtcp2_crypto_conn_ref conn_ref;
        virtual void* get_session() = 0;
        virtual std::string_view selected_alpn() = 0;
        virtual ~TLSSession() = default;
    };

}  // namespace oxen::quic
