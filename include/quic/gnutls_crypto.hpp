#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <optional>

#include "crypto.hpp"

namespace oxen::quic
{
    namespace fs = std::filesystem;

    using gnutls_callback = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;

    constexpr size_t GNUTLS_KEY_SIZE = 32;  // for now, only supporting Ed25519 keys (32 bytes)
    using gnutls_key = std::array<unsigned char, GNUTLS_KEY_SIZE>;

    // arguments: remote pubkey, ALPN
    using gnutls_key_verify_callback = std::function<bool(const gnutls_key&, const std::string_view& alpn)>;

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

                // uint32_t cast to appease narrowing conversion gods,
                // if cert size won't fit in 32 bits we have bigger problems
                mem = {reinterpret_cast<uint8_t*>(input.data()), static_cast<uint32_t>(input.size())};
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
        friend class GNUTLSSession;

      private:
        GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg);

        // Construct from raw Ed25519 keys
        GNUTLSCreds(std::string ed_seed, std::string ed_pubkey, bool snode = false);

        std::vector<std::string> allowed_alpn_strings;
        std::vector<gnutls_datum_t> allowed_alpns;

        std::string outbound_alpn_string;
        gnutls_datum_t outbound_alpn;

      public:
        ~GNUTLSCreds();

        const bool using_raw_pk{false};
        const bool is_snode{false};

        gnutls_certificate_credentials_t cred;

        gnutls_callback_wrapper client_tls_policy{};
        gnutls_callback_wrapper server_tls_policy{};

        gnutls_key_verify_callback key_verify{};

        gnutls_priority_t priority_cache;

        void set_client_tls_policy(
                gnutls_callback func, unsigned int htype = 20, unsigned int when = 1, unsigned int incoming = 0);
        void set_server_tls_policy(
                gnutls_callback func, unsigned int htype = 20, unsigned int when = 1, unsigned int incoming = 0);

        void set_key_verify_callback(gnutls_key_verify_callback cb) { key_verify = std::move(cb); }

        void set_outbound_alpn(const std::string& alpn);
        void set_allowed_alpns(const std::vector<std::string>& alpns);

        static std::shared_ptr<GNUTLSCreds> make(
                std::string remote_key, std::string remote_cert, std::string local_cert = "", std::string ca_arg = "");

        static std::shared_ptr<GNUTLSCreds> make_from_ed_keys(std::string seed, std::string pubkey, bool is_relay = false);

        std::unique_ptr<TLSSession> make_session(bool is_client = false) override;
    };

    class GNUTLSSession : public TLSSession
    {
      private:
        gnutls_session_t session;

        const GNUTLSCreds& creds;
        bool is_client;

        std::optional<gnutls_key> expected_remote_key;

        gnutls_key remote_key;

        void set_tls_hook_functions();  // TODO: which and when?
      public:
        GNUTLSSession(GNUTLSCreds& creds, bool is_client, std::optional<gnutls_key> expected_key = std::nullopt);
        ~GNUTLSSession();

        void* get_session() override { return session; };

        int do_tls_callback(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg) const;

        bool validate_remote_key();
    };

}  // namespace oxen::quic
