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
    inline constexpr auto default_alpn_str = "default"_usv;
    inline constexpr std::chrono::milliseconds DEFAULT_ANTI_REPLAY_WINDOW{10min};

    class TLSSession;
    class Connection;
    struct IOContext;

    class TLSCreds
    {
      public:
        virtual std::unique_ptr<TLSSession> make_session(
                Connection& c, const std::shared_ptr<IOContext>& ctx, const std::vector<ustring>& alpns) = 0;
        virtual ~TLSCreds() = default;
    };

    class TLSSession
    {
      public:
        ngtcp2_crypto_conn_ref conn_ref;
        virtual void* get_session() = 0;
        virtual void* get_anti_replay() const = 0;
        virtual bool get_early_data_accepted() const = 0;
        virtual ustring_view selected_alpn() const = 0;
        virtual ustring_view remote_key() const = 0;
        virtual void set_expected_remote_key(ustring_view key) = 0;
        virtual ~TLSSession() = default;
        virtual int send_session_ticket() = 0;
    };

}  // namespace oxen::quic
