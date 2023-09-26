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
#include <variant>

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

    inline const gnutls_datum_t gnutls_default_alpn{
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(default_alpn_str.data())),
            static_cast<uint32_t>(default_alpn_str.size())};

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
    struct x509_loader
    {
        std::variant<std::string, fs::path> source;
        gnutls_datum_t mem{nullptr, 0};  // Will point at the string content when in_mem() is true
        gnutls_x509_crt_fmt_t format{};

        x509_loader() = default;
        x509_loader(std::string input)
        {
            if (auto path = fs::u8path(input); fs::exists(path))
            {
                format = (str_tolower(path.extension().u8string()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
                source = std::move(path);
            }
            else if (bool pem = starts_with(input, "-----"); pem || (starts_with(input, "\x30") && input.size() >= 48))
            {
                source = std::move(input);
                update_datum();
                format = pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            else
            {
                throw std::invalid_argument{"Invalid cert/key: input is neither a file nor raw valid x509 data"};
            }
        }

      private:
        void update_datum()
        {
            if (auto* s = std::get_if<std::string>(&source))
            {
                mem.data = reinterpret_cast<uint8_t*>(s->data());
                mem.size = s->size();
            }
            else
            {
                mem.data = nullptr;
                mem.size = 0;
            }
        }

      public:
        x509_loader(const x509_loader& other) { *this = other; }
        x509_loader& operator=(const x509_loader& other)
        {
            source = other.source;
            update_datum();
            format = other.format;
            return *this;
        }

        x509_loader(x509_loader&& other) { *this = std::move(other); }
        x509_loader& operator=(x509_loader&& other)
        {
            source = std::move(other.source);
            update_datum();
            format = other.format;
            return *this;
        }

        bool from_mem() const
        {
            auto* s = std::get_if<std::string>(&source);
            return s && !s->empty();
        }

        // returns true if we have either a non-empty path or non-empty raw cert data
        explicit operator bool() const
        {
            return std::visit([](const auto& x) { return !x.empty(); }, source);
        }

        // Implicit conversion to a `const gnutls_datum_t*`.  The datum will point at nullptr if
        // this is not a `from_mem()` instance.
        //
        // Hidden behind a template so that implicit conversion to pointer doesn't cause trouble via
        // other unwanted implicit conversions.
        template <typename T, std::enable_if_t<std::is_same_v<T, gnutls_datum_t>, int> = 0>
        operator const T*() const
        {
            return &mem;
        }

#ifdef _WIN32
      private:
        // On windows we can't return a c string directly from a path (because paths are
        // natively wchar_t-based), so we write the local utf8 path here first when path_cstr is
        // called.
        mutable std::string u8path_buf;

      public:
#endif

        // Implicit conversion to a C string (null terminated `const char*`) containing the path, if
        // this is not a `from_mem()` instance (otherwise returns an empty c string).
        //
        // Hidden behind a template so that implicit conversion to pointer doesn't cause trouble via
        // other unwanted implicit conversions.
        template <typename T, std::enable_if_t<std::is_same_v<T, char>, int> = 0>
        operator const T*() const
        {
            if (auto* p = std::get_if<fs::path>(&source))
            {
#ifdef _WIN32
                u8path_buf = p->u8string();
                return u8path_buf.c_str();
#else
                return p->c_str();
#endif
            }
            return "";
        }
    };

    class GNUTLSCreds : public TLSCreds
    {
        friend class GNUTLSSession;

      private:
        GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg);

        // Construct from raw Ed25519 keys
        GNUTLSCreds(std::string ed_seed, std::string ed_pubkey, bool snode = false);

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

        static std::shared_ptr<GNUTLSCreds> make(
                std::string remote_key, std::string remote_cert, std::string local_cert = "", std::string ca_arg = "");

        static std::shared_ptr<GNUTLSCreds> make_from_ed_keys(std::string seed, std::string pubkey, bool is_relay = false);

        std::unique_ptr<TLSSession> make_session(bool is_client, const std::vector<std::string>& alpns) override;
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
        GNUTLSSession(
                GNUTLSCreds& creds,
                bool is_client,
                const std::vector<std::string>& alpns,
                std::optional<gnutls_key> expected_key = std::nullopt);

        ~GNUTLSSession();

        void* get_session() override { return session; };

        std::string_view selected_alpn() override;

        int do_tls_callback(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg) const;

        bool validate_remote_key();
    };

}  // namespace oxen::quic
