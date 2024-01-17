#pragma once

extern "C"
{
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <memory>

#include "utils.hpp"

namespace oxen::quic
{
    constexpr auto default_alpn_str = "default"sv;

    class TLSSession;
    class Connection;

    class TLSCreds
    {
      public:
        virtual std::unique_ptr<TLSSession> make_session(Connection& c, const std::vector<ustring>& alpns) = 0;
        virtual ~TLSCreds() = default;
    };

    class TLSSession
    {
      public:
        ngtcp2_crypto_conn_ref conn_ref;
        virtual void* get_session() = 0;
        virtual void* get_anti_replay() const = 0;
        virtual const void* get_session_ticket_key() const = 0;
        virtual bool get_early_data_accepted() const = 0;
        virtual ustring_view selected_alpn() = 0;
        virtual ustring_view remote_key() const = 0;
        virtual void set_expected_remote_key(ustring key) = 0;
        virtual ~TLSSession() = default;
        virtual int send_session_ticket() = 0;
    };

}  // namespace oxen::quic
