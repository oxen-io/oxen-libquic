#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include "crypto.hpp"

namespace fs = std::filesystem;

namespace oxen::quic
{
    using gnutls_callback = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;

    struct gnutls_callback_wrapper
    {
        gnutls_callback f = nullptr;
        unsigned int htype = 20;
        unsigned int when = 1;
        unsigned int incoming = 0;

        bool applies(unsigned int h, unsigned int w, unsigned int i) const
        {
            return f && htype == h && when == w && incoming == i;
        }

        operator bool() const { return f != nullptr; }

        template <typename... Args>
        auto operator()(Args&&... args) const
        {
            return f(std::forward<Args>(args)...);
        }
    };

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
        gnutls_x509_crt_fmt_t format{};
        bool from_mem{false};

        datum() = default;
        datum(std::string input) : path{input}
        {
            if (fs::exists(path))
            {
                format = (str_tolower(path.extension().u8string()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                mem.data = nullptr;
                mem.size = 0;
            }
            else
            {
                path = NULL;
                mem = {(uint8_t*)input.data(), (uint8_t)input.size()};
                format = !("-----"s.compare(input.substr(0, 5))) ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                from_mem = true;
            }
        }
        datum(const datum& other) { *this = other; }
        datum& operator=(const datum& other)
        {
            path = other.path;
            std::memcpy(mem.data, other.mem.data, other.mem.size);
            mem.size = other.mem.size;
            format = other.format;
            from_mem = other.from_mem;
            return *this;
        }

        // returns true if path is not empty OR mem has a value set
        explicit operator bool() const noexcept { return (!path.empty() || mem.size); }

        // Hidden behind a template so that implicit conversion to pointer doesn't cause trouble
        template <typename T, typename = std::enable_if_t<std::is_same_v<T, gnutls_datum_t>>>
        operator const T*() const
        {
            return &mem;
        }
    };

    class GNUTLSCreds : public TLSCreds
    {
      private:
        GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg);

      public:
        ~GNUTLSCreds();

        gnutls_certificate_credentials_t cred;

        gnutls_callback_wrapper client_tls_policy{};
        gnutls_callback_wrapper server_tls_policy{};

        void set_client_tls_policy(
                gnutls_callback func, unsigned int htype = 20, unsigned int when = 1, unsigned int incoming = 0);
        void set_server_tls_policy(
                gnutls_callback func, unsigned int htype = 20, unsigned int when = 1, unsigned int incoming = 0);

        static std::shared_ptr<GNUTLSCreds> make(
                std::string remote_key, std::string remote_cert, std::string local_cert = "", std::string ca_arg = "");

        std::unique_ptr<TLSSession> make_session(bool is_client = false) override;
    };

    class GNUTLSSession : public TLSSession
    {
      private:
        gnutls_session_t session;

        const GNUTLSCreds& creds;
        bool is_client;

        void set_tls_hook_functions();  // TODO: which and when?
      public:
        GNUTLSSession(GNUTLSCreds& creds, bool is_client);
        ~GNUTLSSession();

        void* get_session() override { return reinterpret_cast<gnutls_session_t>(session); };

        int do_tls_callback(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg) const;
    };

}  // namespace oxen::quic
