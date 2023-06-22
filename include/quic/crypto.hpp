#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <memory>
#include <type_traits>
#include <unordered_map>

#include "utils.hpp"

namespace fs = std::filesystem;

namespace oxen::quic
{

    using gnutls_callback = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;

    // Struct to wrap cert/key information. Can hold either a string-path, gnutls_datum of the
    // actual key or cert, plus extension and type info.
    // Passable as:
    //      - const char* (ex: to gnutls_certificate_set_x509_key_file)
    //      - gnutls_datum_t* (ex: to gnutls_certificate_set_x509_trust_dir)
    //      - gnutls_x509_crt_fmt_t (ex: to parameter 3 of the above functions)
    struct datum
    {
        fs::path path{};
        gnutls_datum_t mem{};
        gnutls_x509_crt_fmt_t ext{};
        bool from_mem{false};

        datum() = default;
        datum(std::string input) : path{input}
        {
            if (fs::exists(path))
            {
                ext = (str_tolower(path.extension()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                mem.data = nullptr;
                mem.size = 0;
            }
            else
            {
                path = NULL;
                mem = {(uint8_t*)input.data(), (uint8_t)input.size()};
                ext = !("-----"s.compare(input.substr(0, 5))) ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                from_mem = true;
            }
        }
        datum(datum const& other)
        {
            if (!other.path.empty())
                path = other.path;
            memcpy(mem.data, other.mem.data, other.mem.size);
            mem.size = other.mem.size;
            if (ext)
                ext = other.ext;
            from_mem = other.from_mem;
        }

        // returns truew if path is not empty OR mem has a value set
        inline explicit operator bool() const noexcept { return (!path.empty() || mem.size); }

        operator const char*() { return path.c_str(); }
        operator const gnutls_datum_t*() { return &mem; }
        operator gnutls_x509_crt_fmt_t() { return ext; }
    };

    class TLSSession;

    class TLSCreds
    {
      public:
        virtual std::unique_ptr<TLSSession> make_session(const ngtcp2_crypto_conn_ref& conn_ref, bool is_client) = 0;
    };

    // TODO: tls callback functions
    // As far as I can tell, simply not setting a CA and not setting a tls
    // callback function will result in a silent approval, which for our purposes
    // is fine *except* perhaps in Lokinet relay<->relay connections.
    class GNUTLSCreds : public TLSCreds
    {
      private:
        GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg);

      public:
        ~GNUTLSCreds();

        gnutls_certificate_credentials_t cred;

        gnutls_callback client_tls_policy{nullptr};
        gnutls_callback server_tls_policy{nullptr};

        static std::shared_ptr<GNUTLSCreds> make(
                std::string remote_key, std::string remote_cert, std::string local_cert = "", std::string ca_arg = "");

        std::unique_ptr<TLSSession> make_session(const ngtcp2_crypto_conn_ref& conn_ref, bool is_client = false) override;
    };

    class TLSSession
    {
      protected:
        ngtcp2_crypto_conn_ref conn_ref;
        TLSSession(const ngtcp2_crypto_conn_ref& conn_ref) : conn_ref{conn_ref} {}

      public:
        virtual void* get_session() = 0;
    };

    class GNUTLSSession : public TLSSession
    {
      private:
        gnutls_session_t session;

        const GNUTLSCreds& creds;
        bool is_client;

        void set_tls_hook_functions();  // TODO: which and when?
      public:
        GNUTLSSession(GNUTLSCreds& creds, const ngtcp2_crypto_conn_ref& conn_ref_, bool is_client);
        ~GNUTLSSession();

        void* get_session() override { return session; };

        int do_tls_callback(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg) const;
    };

}  // namespace oxen::quic
