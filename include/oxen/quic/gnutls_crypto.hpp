#pragma once

#include "address.hpp"
#include "connection_ids.hpp"
#include "crypto.hpp"
#include "types.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>

extern "C"
{
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
}

#include <array>
#include <chrono>
#include <optional>
#include <variant>

namespace oxen::quic
{
    using namespace oxenc::literals;

    class Connection;

    // Call to enable gnutls trace logging via oxen::logging.  This function does nothing unless
    // libquic is a debug build.
    void enable_gnutls_logging(int level = 99);

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

    /// gnutls_datum_t adapter that frees its data upon destruction.  It is vaguely like unique_ptr,
    /// but with helpers to facilitate interactions with gnutls.
    struct gtls_datum
    {
      private:
        gnutls_datum_t d{NULL, 0};

      public:
        gtls_datum() = default;
        gtls_datum(unsigned char* data, size_t datalen) : d{data, static_cast<unsigned int>(datalen)} {}

        gtls_datum(gtls_datum&&) = default;
        gtls_datum& operator=(gtls_datum&&) = default;
        gtls_datum(const gtls_datum&) = delete;
        gtls_datum& operator=(const gtls_datum&) = delete;

        ~gtls_datum() { reset(); }

        // Frees the data (if any) and replaces the pointer and size with the given ones.
        void reset(unsigned char* data, size_t datalen)
        {
            if (d.data)
            {
                if (sensitive)
                    gnutls_memset(d.data, 0, d.size);
                gnutls_free(d.data);
            }
            d.data = data;
            d.size = datalen;
        }

        // Frees the data (if any) and resets the data pointer to nullptr.  Called automatically on
        // destruction.
        void reset() { reset(nullptr, 0); }

        // Releases ownership of the data *without* freeing it.  I.e. this leaks memory if something
        // else doesn't take over ownership first.
        void release()
        {
            d.data = nullptr;
            d.size = 0;
        }

        // Reset the held data (if any) and replaces it with a newly allocated buffer of the given
        // size.
        void allocate(size_t datalen)
        {
            reset(static_cast<unsigned char*>(gnutls_malloc(datalen)), datalen);
            if (!d.data)
                throw std::bad_alloc{};
        }

        std::span<unsigned char> span() const { return {d.data, d.size}; }

        const unsigned char* data() const { return d.data; }
        unsigned char* data() { return d.data; }

        size_t size() const { return d.size; }
        bool empty() const { return d.size == 0; }

        // If set to true then the data will be overwritten with 0s before being freed.  Should be
        // used on buffers containing sensitive data.
        bool sensitive = false;

        // These operators allow a gtls_datum to be directly passed to any gnutls function taking a
        // gnutls_datum_t*.
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

    struct gtls_key final : std::array<unsigned char, GNUTLS_KEY_SIZE>
    {
        gtls_key() = default;
        gtls_key(const unsigned char* data, size_t size) { write(data, size); }
        explicit gtls_key(std::string_view data) : gtls_key{reinterpret_cast<const unsigned char*>(data.data()), data.size()}
        {}
        explicit gtls_key(std::span<const unsigned char> data) : gtls_key{data.data(), data.size()} {}

        //  Writes to the internal buffer holding the gnutls key
        void write(const unsigned char* buf, size_t size)
        {
            if (size != GNUTLS_KEY_SIZE)
                throw std::invalid_argument{"GNUTLS key must be 32 bytes!"};

            std::memcpy(data(), buf, size);
        }
    };

    // key: remote key to verify, alpn: negotiated alpn's
    using key_verify_callback = std::function<bool(uspan key, std::string_view alpn)>;

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

        static gtls_ticket_ptr make(uspan key, const gnutls_datum_t* ticket)
        {
            return gtls_ticket_ptr(
                    new gtls_session_ticket{key.data(), static_cast<unsigned int>(key.size()), ticket->data, ticket->size});
        }

        // Returns a view of the key for this ticket.  The view is valid as long as this
        // gtls_session_ticket object remains alive, and so can be used (for example) as the key of
        // a map containing the object in the value.
        uspan span() const { return {_key.data(), _key.size()}; }

        // Returns a view of the ticket data.
        uspan ticket() const { return {_ticket.data(), _ticket.size()}; }

        // Accesses the ticket data pointer as needed by gnutls API
        const gnutls_datum_t* datum() const { return &_data; }
        gnutls_datum_t* datum() { return &_data; }
    };

    using store_callback = std::function<void(
            RemoteAddress remote, std::vector<unsigned char> data, std::chrono::system_clock::time_point expiry)>;
    using extract_callback = std::function<std::optional<std::vector<unsigned char>>(const RemoteAddress& remote)>;

    class GNUTLSCreds : public TLSCreds
    {
        friend class GNUTLSSession;

        GNUTLSCreds(std::string_view ed_seed, std::string_view ed_pubkey);

      public:
        static std::shared_ptr<GNUTLSCreds> make_from_ed_keys(std::string_view seed, std::string_view pubkey);
        static std::shared_ptr<GNUTLSCreds> make_from_ed_seckey(std::string_view sk);

        using anti_replay_add_cb = std::function<bool(
                std::span<const unsigned char> key,
                std::span<const unsigned char> value,
                std::chrono::system_clock::time_point expiry)>;

        ~GNUTLSCreds();

        /**
          Calling this method enables support for QUIC server session ticketing and resumption, aka
          0-RTT.

          Enabling 0-RTT potentially reduces reconnection time between a client and a server by
          allowing clients to store session tickets that include enough information to quickly
          resume a session, but comes with two consequences for the early data (i.e. data
          transmitted from client to server before a handshake completes):

          Issue 1: Early data has somewhat less forward secrecy protection than post-handshake data.

          This issue is mitigated by providing a limited validity period for session tickets and
          rotating the key used for session resumption (at three times the validity).  This happens
          automatically by gnutls when 0-RTT is enabled, with a 6h ticket validity (configurable by
          this function).  Longer validity and rotation periods allow issued session tickets to be
          used for longer, but mean the same server key is used for early data encryption for a
          longer period of time, thus reducing forward secrecy.  Increasing the validity period also
          implicitly increases the key rotation period, which means the same key will be used by the
          server for a longer period of time, which is where the reduction in forward secrecy comes
          in: cracking that temporary key allows decrypting all early data over a larger window.

          Issue 2: Early data (i.e.  initial client->server stream or datagram data) is vulnerable
          to a replay attack if replies are not mitigated.

          For example, suppose 0-RTT was used with stream data carrying an instruction to, say,
          initiate a funds transfer.  Although an adversary cannot decrypt this data, they could
          record and replay it, causing the funds transfer to be initiated multiple times.  (Note
          that the response could not be decrypted, nor could any post-handshake client->server data
          be replayed).

          To mitigate this risk, gnutls issues one-time use session tickets which can be stored by a
          client and then used (once) to initiate a new 0-RTT connection (with automatic fallback to
          a full 1-RTT session establishment if the resumption fails).

          On the server side, this is implemented (behind the scenes, by gnutls) by including the
          creation time in the session ticket, and having the client include the ticket age
          (relative to when it received it) as part of session resumption.  The server can then
          compare the ticket timestamp + client's claimed age (plus RTT allowance) and see if the
          time is within a relatively small window around the current server time.  This then allows
          the server to greatly limit the window over which it must store and track tickets for
          replay protection because it can only worry about replay inside the window and simply
          reject any resumption for a ticket outside the window.  Clock adjustments on either side
          could cause false positives, but the consequence of that is simply a fallback to 1-RTT.
          Note that the neither the client nor server clock has to be *correct* for this mechanism
          to work, they merely need to be advancing at (approximately) the same rate.

          This library has a built-in mechanism that uses internal window memory storage to prevent
          replays, but a callback may be provided here for manual storage, if desired.

          Arguments taken by this function to enable 0-RTT:

          - anti_replay_window -- this controls how much leeway there is for clock drift and latency
            differences between client and server from when the ticket was issued until when it is
            later used for session resumption.  Larger values allow larger deviations, but require
            more storage to prevent replays.  0 or negative uses the default (15s).

          - ticket_validity -- this controls how long issued 0-RTT session tickets are valid, and
            implicitly sets the server key rotation for 0-RTT (to three times this value).  0 or
            negative durations will use gnutls's default (6h).  The maximum validity period allowed
            by GNUTLS is one week (604800 seconds).

          - anti_replay_add -- this optional callback allows for manual storage and retrieval of
            anti-replay data.  It is passed three values: a key, a value, and the earliest time at
            which the key may be expired.  If given a nullptr or empty func then default internal
            storage will be used.

            The default anti-replay function (when this is omitted) uses in-memory storage over the
            replay window and is recommended for most cases.

            If the key already exists this callback should return false.  Otherwise the key should
            be stored and true returned.  The expiry timestamp provides the earliest point at which
            stored entry may be cleaned up.

            Anti-replay entry cleanup is the responsibility of the caller when using this function:
            it could be done as part of the lookup function itself, or on a separate timer.  It is
            __not__ required that the lookup function take entry expiry into account: allowing a
            false return for an expired entry is harmless (it is simply provides some redundant
            anti-replay protection).

          - master_key -- this can be used to set a gnutls session ticket master key (as obtained
            via `GNUTLSCreds::create_0rtt_master_key`) for the initial key and from which rotated
            session ticket keys are derived.  The primary purpose of this option is to allow 0-RTT
            resumption across different instances, where those different instances are started at
            the same time (such as for load balancing).  Note that this does *not* allow resumption
            across restarts: gnutls will refuse to use a ticket created before it started.  The
            value provided here should never be deterministic or reused except for the multiple
            instances case.

            If at all unsure, do not specify this key so that a new random master key will be
            securely generated.

            When using a master_key you *must* provide a custom anti_replay_add implementation that
            provides anti-replay lookup across the multiple instances that are sharing the same
            master key.  (The default anti_replay implementation does not provide that capability).

            You can generate an acceptable master key with the create_0rtt_master_key function.


          Note that this function only enables the server-side of 0-RTT: to make use of it from a
          client the client must also be using a GNUTLSCreds object with `enable_outbound_0rtt(...)`.
         */
        void enable_inbound_0rtt(
                std::chrono::milliseconds anti_replay_window = 0s,
                std::chrono::seconds ticket_validity = 0s,
                anti_replay_add_cb anti_replay_add = nullptr,
                std::span<const unsigned char> master_key = {});

        /// Returns true if inbound 0-RTT support has been enabled.
        bool inbound_0rtt() const override { return !session_ticket_key.empty(); }

        /// Call to generate a master key that can be given to `enable_inbound_0rtt(...)`.  See that
        /// function's documentation for details.  (The value is provided via callback, rather than
        /// returned, as it will be securely erased before the internal copy is freed.)
        static std::vector<unsigned char> create_0rtt_master_key();

        /**
          Calling this method enables client-side (i.e. outgoing connection) support for 0-RTT
          connections.

          This requires using previously-issued session data for the remote (consisting, opaquely,
          of a TLS session ticket as well as QUIC server transport parameters), with storage managed
          by the two function calls provided here.

          See enable_inbound_0rtt, above, for the an overall description of how TLS ticketing works,
          the possible drawbacks of enabling 0-RTT, and the server-side implementation that must be
          provided on the server side to issue the required session tickets to allow 0-RTT
          connections to happen.

          Arguments:
          - store -- this is called whenever a TLS session ticket is received from the server, and
            should be stored for later (possible) use when connecting again to the same server.
            The callback is invoked with:
               - the RemoteAddress (i.e. both pubkey and address).  It can be sufficient to key the
                 entries on just the pubkey, but applications may have a need to also use the
                 address for keying (for example, if the same libquic Endpoint was being used to
                 connect to two different services sharing the same primary pubkey).
               - the opaque data to be stored (which contains both the TLS session ticket data and
                 the QUIC-required server transport parameters)
               - the session data expiry timestamp, which is intended to be used to clean up
                 obsolete data.

            Note that multiple tickets can be and typically are provided for a given server
            connection, and so this function should ideally be able to store multiple data (i.e.
            not just the latest one given).  It is recommended that, at a minimum, the two most
            recent tickets are stored but an application could store more or all unexpired items for
            a given remote.

          - extract -- this is called to obtain a session ticket for a connection to the server with
            the given RemoteAddress.  (Whether the full address+pubkey is matched or just the pubkey
            is up to the application; see `store`).  If one or more tickets are found, this should
            choose one (typically the most recently received or further from expiry), delete it from
            storage (tickets cannot be reused) and return the stored session data as it was provided
            to the `store` function.  If no match is found the call should return nullopt, in which
            case the connection will fall back to 1-RTT.

          If you omit (or give a default-constructed or nullptr value) for both functions then
          internal versions will be used that preserve up to three most recently provided tickets
          for each remote, matching on both pubkey and remote address.  This default version will
          allow 0-RTT upon reconnection from the same endpoint, but has no ability to use 0-RTT if
          the endpoint or application is restarted, or across endpoints.

          It is an error to provide just one of the two callbacks which will result in a
          std::invalid_argument exception.

          Note that 0-RTT is only actually used for establishing a connection if the extract
          function returns session data; if no data is found then 1-RTT will be used.  The `extract`
          function is not required to return stored data: it could deliberately return nullopt if
          application logic has a reason to force 1-RTT, even if session data for 0-RTT is
          available; the `store` function will still be given session tickets even if 0-RTT was not
          used for the connection.
         */
        void enable_outbound_0rtt(store_callback store = {}, extract_callback extract = {});

        /// Returns true if outbound 0-RTT callbacks have been configured.
        bool outbound_0rtt() const override { return static_cast<bool>(session_extract); }

      private:
        gnutls_pcert_st pcrt;
        gnutls_privkey_t pkey;
        const bool using_raw_pk{false};

        gnutls_certificate_credentials_t cred;

        key_verify_callback key_verify;

        gnutls_priority_t priority_cache;

        gtls_datum session_ticket_key{};
        int session_ticket_expiration = 0;
        gnutls_anti_replay_t anti_replay = nullptr;
        anti_replay_add_cb anti_replay_add;
        store_callback session_store;
        extract_callback session_extract;

        friend int anti_replay_store(void*, time_t, const gnutls_datum_t*, const gnutls_datum_t*);

        void store_session_ticket(Connection& conn, RemoteAddress addr, std::span<const unsigned char> ticket_data) override;

        std::optional<session_data> extract_session_data(const RemoteAddress& addr) override;

      public:
        std::unique_ptr<TLSSession> make_session(
                Connection& c,
                const IOContext& ctx,
                std::span<const std::string> alpns,
                std::optional<std::span<const unsigned char>> expected_remote_key) override;

        void load_keys(x509_loader& seed, x509_loader& pk);

        void set_key_verify_callback(key_verify_callback cb) { key_verify = std::move(cb); }
    };

    class GNUTLSSession : public TLSSession
    {
      public:
        const GNUTLSCreds& creds;

      private:
        gnutls_session_t session;

        const bool _is_client;

        std::string _selected_alpn{};
        std::optional<gtls_key> _expected_remote_key;
        gtls_key _remote_key{};
        std::optional<std::vector<unsigned char>> _0rtt_tp_data;

        void set_selected_alpn();

      public:
        GNUTLSSession(
                GNUTLSCreds& creds,
                const IOContext& ctx,
                Connection& c,
                std::span<const std::string> alpns,
                std::optional<gtls_key> expected_key = std::nullopt);

        ~GNUTLSSession();

        void* get_session() override { return session; }

        // Extract quic objects from gnutls objects.  Precondition: the gnutls session must actually
        // be one that we set up, and the associated Connection must actually use a GNUTLSSession.
        static GNUTLSSession& from(gnutls_session_t g_session);
        static GNUTLSSession& from(Connection& conn);
        static Connection& conn_from(gnutls_session_t g_session);

        bool get_early_data_accepted() const override
        {
            return gnutls_session_get_flags(session) & GNUTLS_SFLAGS_EARLY_DATA;
        }

        std::span<const unsigned char> remote_key() const override { return _remote_key; }

        std::string_view selected_alpn() const override { return _selected_alpn; }

        bool validate_remote_key();

        std::optional<std::vector<unsigned char>> extract_0rtt_tp_data() override { return std::move(_0rtt_tp_data); }

        void send_session_tickets() override;
    };

}  // namespace oxen::quic

// gtls_key hasher
template <>
struct std::hash<oxen::quic::gtls_key>
{
    size_t operator()(const oxen::quic::gtls_key& key) const
    {
        return std::hash<std::string_view>{}(std::string_view{reinterpret_cast<const char*>(key.data()), key.size()});
    }
};
