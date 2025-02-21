#pragma once

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/format.hpp>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

extern "C"
{
#include <unistd.h>
}

namespace oxen::quic
{
    extern bool disable_ipv6, disable_rotating_buffer, disable_0rtt;

    namespace log = oxen::log;
    using namespace log::literals;
    inline auto test_cat = log::Cat("quic-test");

    // Borrowing these from src/internal.hpp:
    void logger_config(std::string out = "stderr", log::Type type = log::Type::Print, log::Level reset = log::Level::trace);
    inline auto log_cat = log::Cat("quic");

    using namespace oxenc::literals;

    inline const std::string LOCALHOST = "127.0.0.1"s;
    inline const std::string TEST_ENDPOINT = "test_endpoint"s;
    inline const std::string TEST_BODY = "test_body"s;

    inline const Address DEFAULT_SPEEDTEST_ADDR{LOCALHOST, uint16_t{5500}};
    inline const Address DEFAULT_DGRAM_SPEED_ADDR{LOCALHOST, uint16_t{5501}};
    inline const Address DEFAULT_PING_ADDR{LOCALHOST, uint16_t{5502}};

    class TestHelper
    {
      public:
        static void migrate_connection(Connection& conn, Address new_bind);

        static void migrate_connection_immediate(Connection& conn, Address new_bind);

        static void nat_rebinding(Connection& conn, Address new_bind);

        static void set_endpoint_local_addr(Endpoint& ep, Address new_local);

        static void enable_dgram_drop(connection_interface& conn);
        static int disable_dgram_drop(connection_interface& conn);
        static void enable_dgram_counter(connection_interface& conn);
        static int disable_dgram_counter(connection_interface& conn);
        static int get_dgram_debug_counter(connection_interface& conn);

        // Bumps the connection's next reference id to make it easier to tell which connection is
        // which in log output.
        static void increment_ref_id(Endpoint& ep, uint64_t by = 1);

        static Connection* get_conn(std::shared_ptr<Endpoint>& ep, std::shared_ptr<connection_interface>& conn);

        static UDPSocket::socket_t get_sock(Endpoint& ep);
    };

    namespace test::defaults
    {
        inline std::pair<std::string, std::string> CLIENT_KEYS, SERVER_KEYS;
        inline const std::string& CLIENT_SEED = CLIENT_KEYS.first;
        inline const std::string& CLIENT_PUBKEY = CLIENT_KEYS.second;
        inline const std::string& SERVER_SEED = SERVER_KEYS.first;
        inline const std::string& SERVER_PUBKEY = SERVER_KEYS.second;

        std::pair<std::shared_ptr<GNUTLSCreds>, std::shared_ptr<GNUTLSCreds>> tls_creds_from_ed_keys();
    }  // namespace test::defaults

    void sha3_256(uint8_t* out, std::span<const uint8_t> value, std::string_view domain = "");
    void sha3_256(uint8_t* out, std::span<const char> value, std::string_view domain = "");
    void sha3_512(uint8_t* out, std::span<const uint8_t> value, std::string_view domain = "");
    void sha3_512(uint8_t* out, std::span<const char> value, std::string_view domain = "");

    // Generates an Ed25519 keypair for testing purposes.  Returned values are the 32-byte seed and
    // 32-byte pubkey.  If you provide a seed_string, then that string is hashed to produce the
    // Ed25519 seed instead of generating a secure random one.  (Note that this generation mode is
    // not secure and is only to allow reproducible quasi-random test suite keys but should not
    // otherwise be used).
    std::pair<std::string, std::string> generate_ed25519(std::string_view seed_string = ""sv);

    // Generates a static secret for testing purposes.  Like generate_ed25519, this will use a hash
    // of the given seed, if non-empty, and otherwise will generate a random value.
    opt::static_secret generate_static_secret(std::string_view seed_string = ""sv);

    template <oxenc::const_span_type T>
    inline std::string_view sp_to_sv(const T& sp)
    {
        return {reinterpret_cast<const char*>(sp.data()), sp.size()};
    }

    // Takes a hex- or base64-encoded byte value of the given byte size and returns the bytes.
    // Returns nullopt if the encoded value is not a valid byte encoding of the given size.
    std::optional<std::string> decode_bytes(std::string_view encoded, size_t size = 32);

    // Adds common logging options
    void add_log_opts(CLI::App& cli, std::string& file, std::string& level);

    // Adds common server options.
    void common_server_opts(CLI::App& cli, std::string& server_listen, std::string& seed_string, bool& enable_0rtt);

    // Adds common client options.
    void common_client_opts(
            CLI::App& cli,
            std::string& local_addr,
            std::string& remote_addr,
            std::string& remote_pubkey,
            std::string& seed_string,
            bool& enable_0rtt,
            std::filesystem::path& store_0rtt);

    void setup_logging(std::string out, const std::string& level);

    void server_log_listening(
            const Address& server_local,
            const Address& default_local,
            const std::string& pubkey,
            const std::string& seed_string,
            bool enable_0rtt,
            std::string_view extra = ""sv);

    /// RAII class that resets the log level for the given category while the object is alive, then
    /// resets it to what it was at construction when the object is destroyed.
    struct log_level_override
    {
        log::Level previous;
        log_level_override(log::Level l, std::string category = "quic") : previous{log::get_level(category)}
        {
            log::set_level(category, l);
        }
        ~log_level_override() { log::set_level("quic", previous); }
    };

    /// Same as above, but only raises the log level to a more serious cutoff (leaving it alone if
    /// already higher).
    struct log_level_raiser : log_level_override
    {
        log_level_raiser(log::Level l, std::string category = "quic") :
                log_level_override{std::max(l, log::get_level(category)), category}
        {}
    };
    /// Same as above, but only lowers the log level to a more frivolous cutoff (leaving it alone if
    /// already lower).
    struct log_level_lowerer : log_level_override
    {
        log_level_lowerer(log::Level l, std::string category = "quic") :
                log_level_override{std::min(l, log::get_level(category)), category}
        {}
    };

#define _require_future2(f, timeout) REQUIRE(f.wait_for(timeout) == std::future_status::ready)
#define _require_future1(f) _require_future2(f, 1s)
#define GET_REQUIRE_FUTURE_MACRO(_1, _2, NAME, ...) NAME
#define require_future(...) GET_REQUIRE_FUTURE_MACRO(__VA_ARGS__, _require_future2, _require_future1)(__VA_ARGS__)

    template <typename T>
    struct functional_helper : public functional_helper<decltype(&T::operator())>
    {};

    template <typename Class, typename Ret, typename... Args>
    struct functional_helper<Ret (Class::*)(Args...) const>
    {
        using return_type = Ret;
        static constexpr bool is_void = std::is_void_v<Ret>;
        using type = std::function<Ret(Args...)>;
    };

    template <typename T>
    using functional_helper_t = typename functional_helper<T>::type;

    struct set_on_exit
    {
        std::promise<void>& p;
        explicit set_on_exit(std::promise<void>& p) : p{p} {}
        ~set_on_exit() { p.set_value(); }
    };

    /// Test suite helper that takes a callable lambda at construction and then man-in-the-middles
    /// an intermediate std::function matching the lambda that calls the inner lambda but also sets
    /// a promise just after calling the inner lambda.
    ///
    /// The main purpose is to synchronize an asynchronous interface with a promise/future to
    /// simplify test code which is full of "wait for this thing to be called" checks, without
    /// needing any sort of sleep & poll (and reducing the direct usage of promise/futures in the
    /// test suite).
    ///
    /// Usage example:
    ///
    ///     int foo = 0;
    ///     callback_waiter waiter{[&foo](int a, int b) { foo = a + b; }};
    ///     invoke_something(waiter);
    ///
    /// where `invoke_something` takes a `std::function<int(Foo&, int)>`.  The test code would then
    /// go on to synchronize with:
    ///
    ///     REQUIRE(waiter.wait(/* 5s */)); // will fail if the lambda doesn't get called within ~5s
    ///
    /// and then can go on to check side effects of the lambda, e.g.:
    ///
    ///     CHECK(foo == 42);
    ///
    /// Care must be taken to ensure the lambda is only called once.  The lambda may throw, but the
    /// throw propagates to the caller of the lambda, *not* the inner promise.
    template <typename T>
    struct callback_waiter
    {
        using Func_t = functional_helper_t<T>;

        Func_t func;
        std::shared_ptr<std::promise<void>> p{std::make_shared<std::promise<void>>()};
        std::future<void> f{p->get_future()};

        explicit callback_waiter(T f) : func{std::move(f)} {}

        [[nodiscard]] bool wait(std::chrono::milliseconds timeout = 5s)
        {
            return f.wait_for(timeout) == std::future_status::ready;
        }

        [[nodiscard]] bool is_ready() { return wait(0s); }

        // Deliberate implicit conversion to the std::function<...>
        operator Func_t()
        {
            return [p = p, func = func](auto&&... args) {
                set_on_exit prom_setter{*p};
                return func(std::forward<decltype(args)>(args)...);
            };
        }
    };

    // Helper class for persistent zerortt storage.  This loads from disk on construction, and
    // replaces the content on disk whenever a new entry is added.
    struct zerortt_storage
    {
        // pubkey -> list of [ticketdata, expiry]
        using zerortt_data_t = std::unordered_map<std::string, std::list<std::pair<std::string, int64_t>>>;

        std::filesystem::path path;
        zerortt_data_t data;

        explicit zerortt_storage(std::filesystem::path p);

        // Load/save to disk.  Called automatically on construction and when storing a new entry.
        void load(bool prune_expired = true);
        void dump(bool prune_expired = true);

        // Cleans up expired entries.  Returns true if anything changed.
        bool clear_expired();

        // Stores new session data
        void store(
                const RemoteAddress& remote,
                std::vector<unsigned char> vdata,
                std::chrono::system_clock::time_point expiry,
                bool dump = true);
        // Looks up a remote by key, removing and returning the most recently added non-expired
        // session data.  Returns nullopt if no session data was found.
        std::optional<std::vector<unsigned char>> extract(const RemoteAddress& remote, bool dump = true);

        // Enables zerortt for the given creds using persistent storage via an instance of this class.
        static void enable(GNUTLSCreds& creds, std::filesystem::path path);
    };

    // Returns a human-readable duration, auto-scaling the unit based on the duration given.
    std::string friendly_duration(std::chrono::nanoseconds dur);

    // Kills the Network held in `net` with endpoint `ep` without allowing it to send closes and
    // whatnot, by removing its socket it from under it.  After the call, `net`, `ep`, and any
    // ancillary `other...` shared points will all be empty.  Does nothing if `net` is already
    // empty.
    template <typename... SP_T>
    static void kill_network(std::unique_ptr<Network>& net, std::shared_ptr<Endpoint>& ep, std::shared_ptr<SP_T>&... other)
    {
        if (!net)
            return;

        assert(ep);
        auto sock = TestHelper::get_sock(*ep);
        log::debug(test_cat, "dirty-closing endpoint socket");
#ifdef _WIN32
        ::closesocket(sock);
#else
        ::close(sock);
#endif

        log::debug(test_cat, "releasing endpoint and {} other objects", sizeof...(other));
        ep.reset();
        (other.reset(), ...);

        log::debug(test_cat, "dirty-closing Network");
        net->set_shutdown_immediate();
        net.reset();

        log::debug(test_cat, "Network killed!");
    }

    // Manual packet delivery system that delays all packet transmission by a configurable amount of
    // time; used to test things like 0rtt where we can use the delay to test whether data is
    // arriving before a handshake could have completed.  The delay is applied to both incoming and
    // outgoing packets, and so should generally be used on just one side of the connection.
    //
    // This is quite event loop heavy as every packet is separately queued via a timer on the end
    // loop and is not meant to be particularly performant.
    //
    // To use this you must:
    // - construct this object via `auto delayer = packet_delayer::make(10ms);`
    // - construct the endpoint, passing `*delayer` to the `endpoint(...)` call (this object
    //   auto-converts into the appropriate manual routing option).
    // - call `delayer->init(loop, ep)`, providing a loop and the endpoint (it does not have to be
    //   the endpoint's loop), which starts the actual underlying socket.
    class packet_delayer : public std::enable_shared_from_this<packet_delayer>
    {
      public:
        std::atomic<std::chrono::milliseconds> delay;

      private:
        std::shared_ptr<Loop> loop;
        std::shared_ptr<Endpoint> ep;
        std::unique_ptr<UDPSocket> sock;

        explicit packet_delayer(std::chrono::milliseconds delay) : delay{delay} {}

      public:
        static std::shared_ptr<packet_delayer> make(std::chrono::milliseconds delay = 10ms);

        // Non-copyable, non-movable:
        packet_delayer(packet_delayer&&) = delete;
        packet_delayer(const packet_delayer&) = delete;
        packet_delayer& operator=(packet_delayer&&) = delete;
        packet_delayer& operator=(const packet_delayer&) = delete;

        operator opt::manual_routing();

        void init(std::shared_ptr<Loop>, std::shared_ptr<Endpoint> ep);
    };

}  // namespace oxen::quic
