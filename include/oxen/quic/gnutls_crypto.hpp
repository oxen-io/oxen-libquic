#pragma once

#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <array>
#include <optional>
#include <variant>

#include "connection_ids.hpp"
#include "crypto.hpp"
#include "types.hpp"

namespace oxen::quic
{
    using namespace oxenc::literals;

    class Connection;

    std::string translate_key_format(gnutls_x509_crt_fmt_t crt);

    std::string translate_cert_type(gnutls_certificate_type_t type);

    std::string get_cert_type(gnutls_session_t session, gnutls_ctype_target_t type);

    extern "C"
    {
        int cert_verify_callback_gnutls(gnutls_session_t g_session);

        void gnutls_log(int level, const char* str);

        struct gnutls_log_setter
        {
            gnutls_log_setter()
            {
                gnutls_global_set_log_level(99);
                gnutls_global_set_log_function(gnutls_log);
            }
        };
    }

    namespace fs = std::filesystem;

    using gnutls_callback = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;

    inline constexpr size_t CERT_HEADER_SIZE = 12;
    inline constexpr size_t GNUTLS_KEY_SIZE = 32;  // for now, only supporting Ed25519 keys (32 bytes)
    inline constexpr size_t GNUTLS_SECRET_KEY_SIZE = 64;

    // These bytes mean "this is a raw Ed25519 private key" in ASN.1 (or something like that)
    inline constexpr auto ASN_ED25519_SEED_PREFIX = "302e020100300506032b657004220420"_hex;
    // These bytes mean "this is a raw Ed25519 public key" in ASN.1 (or something like that)
    inline constexpr auto ASN_ED25519_PUBKEY_PREFIX = "302a300506032b6570032100"_hex;

    struct gtls_datum
    {
      private:
        gnutls_datum_t d{NULL, 0};

      public:
        gtls_datum() = default;
        gtls_datum(unsigned char* data, size_t datalen) : d{data, static_cast<unsigned int>(datalen)} {}

        ~gtls_datum() { reset(); }

        void reset()
        {
            if (d.data != NULL)
                gnutls_free(d.data);
            d.size = 0;
        }

        ustring_view view() const { return {d.data, d.size}; }

        const unsigned char* data() const { return d.data; }
        unsigned char* data() { return d.data; }

        size_t size() const { return d.size; }

        template <std::same_as<gnutls_datum_t> T>
        operator const T*() const
        {
            return &d;
        }

        template <std::same_as<gnutls_datum_t> T>
        operator T*()
        {
            return &d;
        }
    };

    struct gtls_key
    {
      private:
        std::array<unsigned char, GNUTLS_KEY_SIZE> buf{};

        gtls_key(const unsigned char* data, size_t size) { write(data, size); }

      public:
        gtls_key() = default;
        gtls_key(std::string_view data) : gtls_key{convert_sv<unsigned char>(data)} {}
        gtls_key(ustring_view data) : gtls_key{data.data(), data.size()} {}

        //  Writes to the internal buffer holding the gnutls key
        void write(const unsigned char* data, size_t size)
        {
            if (size != GNUTLS_KEY_SIZE)
                throw std::invalid_argument{"GNUTLS key must be 32 bytes!"};

            std::memcpy(buf.data(), data, size);
        }

        ustring_view view() const { return {buf.data(), buf.size()}; }

        gtls_key(const gtls_key& other) { *this = other; }

        gtls_key& operator=(const gtls_key& other)
        {
            buf = other.buf;
            return *this;
        }

        void operator()(ustring_view data) { write(data.data(), data.size()); }

        explicit operator bool() const { return not buf.empty(); }

        bool operator==(const gtls_key& other) const { return buf == other.buf; }
        bool operator!=(const gtls_key& other) const { return !(*this == other); }
    };

    // key: remote key to verify, alpn: negotiated alpn's
    using key_verify_callback = std::function<bool(const ustring_view& key, const ustring_view& alpn)>;

    inline const gnutls_datum_t GNUTLS_DEFAULT_ALPN{
            const_cast<unsigned char*>(default_alpn_str.data()), default_alpn_str.size()};

    struct gnutls_callback_wrapper
    {
        gnutls_callback cb{nullptr};
        unsigned int htype{20};
        unsigned int when{1};
        unsigned int incoming{0};

        bool applies(unsigned int h, unsigned int w, unsigned int i) const
        {
            return cb && htype == h && when == w && incoming == i;
        }

        operator bool() const { return cb != nullptr; }

        template <typename... Args>
        auto operator()(Args&&... args) const
        {
            return cb(std::forward<Args>(args)...);
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
        gnutls_datum_t mem;  // Will point at the string content when in_mem() is true
        gnutls_x509_crt_fmt_t format{};

        // x509_loader() = default;
        x509_loader(std::string input)
        {
            if (auto path = fs::path(
#ifdef _WIN32
                        std::u8string{reinterpret_cast<char8_t*>(input.data()), input.size()}
#else
                        input
#endif
                );
                fs::exists(path))
            {
#ifdef _WIN32
                auto p8_str = path.extension().u8string();
                auto path_str = std::string{reinterpret_cast<const char*>(p8_str.data()), p8_str.size()};

                format = (str_tolower(path_str) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
#else
                format = (str_tolower(path.extension().string()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
#endif
                source = std::move(path);
            }
            else if (bool pem = input.starts_with("-----"); pem || (input.starts_with("\x30") && input.size() >= 48))
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
                mem.data = reinterpret_cast<unsigned char*>(s->data());
                mem.size = static_cast<unsigned int>(s->size());
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
            format = std::move(other.format);
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
        template <std::same_as<gnutls_datum_t> T>
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
        template <typename T>
            requires std::same_as<T, char>
        operator const T*() const
        {
            if (auto* p = std::get_if<fs::path>(&source))
            {
#ifdef _WIN32
                auto u8_path = p->u8string();
                u8path_buf = std::string{reinterpret_cast<const char*>(u8_path.data()), u8_path.size()};
                return u8path_buf.c_str();
#else
                return p->c_str();
#endif
            }
            return "";
        }
    };

    struct gtls_session_ticket;
    using gtls_ticket_ptr = std::unique_ptr<gtls_session_ticket>;

    struct gtls_session_ticket
    {
      private:
        const std::vector<unsigned char> _key;
        std::vector<unsigned char> _ticket;
        // do not double free; points to vector data that will be freed already
        gnutls_datum_t _data;

        explicit gtls_session_ticket(
                const unsigned char* key, unsigned int keysize, const unsigned char* ticket, unsigned int ticketsize) :
                _key{key, key + keysize}, _ticket{ticket, ticket + ticketsize}, _data{_ticket.data(), ticketsize}
        {}

        explicit gtls_session_ticket(ustring_view key, ustring_view ticket) :
                gtls_session_ticket{
                        key.data(),
                        static_cast<unsigned int>(key.size()),
                        ticket.data(),
                        static_cast<unsigned int>(ticket.size())}
        {}

      public:
        gtls_session_ticket() = delete;
        gtls_session_ticket(gtls_session_ticket&& t) = delete;
        gtls_session_ticket(const gtls_session_ticket& t) = delete;
        gtls_session_ticket& operator=(gtls_session_ticket&&) = delete;
        gtls_session_ticket& operator=(const gtls_session_ticket&) = delete;

        static gtls_ticket_ptr make(const gnutls_datum_t* key, const gnutls_datum_t* ticket)
        {
            return gtls_ticket_ptr(new gtls_session_ticket{key->data, key->size, ticket->data, ticket->size});
        }

        static gtls_ticket_ptr make(ustring_view key, const gnutls_datum_t* ticket)
        {
            return gtls_ticket_ptr(
                    new gtls_session_ticket{key.data(), static_cast<unsigned int>(key.size()), ticket->data, ticket->size});
        }

        // Returns a view of the key for this ticket.  The view is valid as long as this
        // gtls_session_ticket object remains alive, and so can be used (for example) as the key of
        // a map containing the object in the value.
        ustring_view key() const { return {_key.data(), _key.size()}; }

        // Returns a view of the ticket data.
        ustring_view ticket() const { return {_ticket.data(), _ticket.size()}; }

        // Accesses the ticket data pointer as needed by gnutls API
        const gnutls_datum_t* datum() const { return &_data; }
        gnutls_datum_t* datum() { return &_data; }
    };

    struct Packet;

    struct gtls_reset_token
    {
        static constexpr size_t TOKENSIZE{NGTCP2_STATELESS_RESET_TOKENLEN};
        static constexpr size_t RANDSIZE{NGTCP2_MIN_STATELESS_RESET_RANDLEN};

      private:
        gtls_reset_token(const uint8_t* _tok, const uint8_t* _rand = nullptr);
        gtls_reset_token(uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid);

      public:
        std::array<uint8_t, TOKENSIZE> _tok{};
        std::array<uint8_t, RANDSIZE> _rand{};

        const uint8_t* token() { return _tok.data(); }
        const uint8_t* rand() { return _rand.data(); }

        static void generate_token(uint8_t* buffer, uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid);
        static void generate_rand(uint8_t* buffer);
        static std::shared_ptr<gtls_reset_token> generate(uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid);
        static std::shared_ptr<gtls_reset_token> make_copy(const uint8_t* tok_buf, const uint8_t* rand_buf = nullptr);
        static std::shared_ptr<gtls_reset_token> parse_packet(const Packet& pkt);

        auto operator<=>(const gtls_reset_token& t) const { return std::tie(_tok, _rand) <=> std::tie(t._tok, t._rand); }
        bool operator==(const gtls_reset_token& t) const { return (*this <=> t) == 0; }
    };

    class GNUTLSCreds : public TLSCreds
    {
        friend class GNUTLSSession;

        GNUTLSCreds(std::string_view ed_seed, std::string_view ed_pubkey);

      public:
        static std::shared_ptr<GNUTLSCreds> make_from_ed_keys(std::string_view seed, std::string_view pubkey);
        static std::shared_ptr<GNUTLSCreds> make_from_ed_seckey(std::string_view sk);

        ~GNUTLSCreds();

      private:
        gnutls_pcert_st pcrt;
        gnutls_privkey_t pkey;
        const bool using_raw_pk{false};

        gnutls_certificate_credentials_t cred;

        key_verify_callback key_verify;

        gnutls_priority_t priority_cache;

      public:
        std::unique_ptr<TLSSession> make_session(
                Connection& c, const std::shared_ptr<IOContext>&, const std::vector<ustring>& alpns) override;

        void load_keys(x509_loader& seed, x509_loader& pk);

        void set_key_verify_callback(key_verify_callback cb) { key_verify = std::move(cb); }
    };

    class GNUTLSSession : public TLSSession
    {
      public:
        const GNUTLSCreds& creds;

      private:
        gnutls_session_t session;
        gtls_datum session_ticket_key{};
        gnutls_anti_replay_t anti_replay;

        const bool _is_client;
        const bool _0rtt_enabled;

        ustring _selected_alpn{};
        gtls_key _expected_remote_key{};
        gtls_key _remote_key{};

        void set_selected_alpn();

      public:
        GNUTLSSession(
                GNUTLSCreds& creds,
                const std::shared_ptr<IOContext>& ctx,
                Connection& c,
                const std::vector<ustring>& alpns,
                std::optional<gtls_key> expected_key = std::nullopt);

        ~GNUTLSSession();

        void* get_session() override { return session; }

        void* get_anti_replay() const override { return anti_replay; }

        bool get_early_data_accepted() const override
        {
            return gnutls_session_get_flags(session) & GNUTLS_SFLAGS_EARLY_DATA;
        }

        ustring_view remote_key() const override { return _remote_key.view(); }

        ustring_view selected_alpn() const override { return _selected_alpn; }

        bool validate_remote_key();

        int send_session_ticket() override;

        void set_expected_remote_key(ustring_view key) override { _expected_remote_key(key); }
    };

    GNUTLSSession* get_session_from_gnutls(gnutls_session_t g_session);
    Connection* get_connection_from_gnutls(gnutls_session_t g_session);

}  // namespace oxen::quic
