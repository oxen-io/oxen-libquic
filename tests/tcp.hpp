#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
}

#include <future>
#include <thread>

#include "utils.hpp"

namespace oxen::quic
{
    struct TCPConnection;
    class TCPHandle;

    inline const auto LOCALHOST = "127.0.0.1"s;
    inline constexpr auto TUNNEL_SEED = "0000000000000000000000000000000000000000000000000000000000000000"_hex;
    inline constexpr auto TUNNEL_PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"_hex;

    inline constexpr size_t HIGH_WATERMARK{4_Mi};
    inline constexpr size_t LOW_WATERMARK{HIGH_WATERMARK / 2};

    inline constexpr size_t TCP_HIGHWATER{2_Mi};
    inline constexpr size_t TCP_LOWWATER{TCP_HIGHWATER / 2};

    namespace CODE
    {
        inline constexpr uint64_t STOP_READING{STREAM_REMOTE_READ_SHUTDOWN};
        inline constexpr uint64_t STOP_WRITING{STREAM_REMOTE_WRITE_SHUTDOWN};
        inline constexpr uint64_t STOP_NOW{STOP_WRITING + 1};
    }  // namespace CODE

    inline std::vector<std::byte> serialize_payload(bstring_view data, uint16_t port = 0)
    {
        std::vector<std::byte> ret(data.size() + sizeof(port));
        oxenc::write_host_as_big(port, ret.data());
        std::memcpy(&ret[2], data.data(), data.size());
        return ret;
    }

    inline std::tuple<uint16_t, bstring> deserialize_payload(bstring data)
    {
        uint16_t p = oxenc::load_big_to_host<uint16_t>(data.data());

        return {p, data.substr(2)};
    }

    struct TCPQUIC
    {
        std::shared_ptr<connection_interface> _ci;

        // keyed against backend tcp address
        std::unordered_map<Address, std::unordered_set<std::shared_ptr<TCPConnection>>> _tcp_conns;
    };

    // held in a map keyed against the remote address
    struct tunneled_connection
    {
        std::shared_ptr<TCPHandle> h;

        // keyed against the remote port (for tunnel_client) or local port (for tunnel_server)
        std::unordered_map<uint16_t, TCPQUIC> conns;
    };

    inline constexpr auto evconnlistener_deleter = [](::evconnlistener* e) {
        log::trace(test_cat, "Invoking evconnlistener deleter!");
        if (e)
            evconnlistener_free(e);
    };

    void initiator_stream_reset_cb(struct bufferevent* bev, Stream& s, uint64_t ec, void* user_arg);
    void receiver_stream_reset_cb(struct bufferevent* bev, Stream& s, uint64_t ec, void* user_arg);

    void _stop_now_cb(struct bufferevent* bev, Stream& s, void* user_arg, bool is_initiator);

    bool _flush_now_cb(struct bufferevent* bev, Stream& s, void* user_arg, bool is_initiator);

    void tcp_drained_write_free_cb(struct bufferevent* bev, void* user_arg);

    void client_drained_write_close_cb(struct bufferevent* bev, void* user_arg);
    void server_drained_write_close_cb(struct bufferevent* bev, void* user_arg);

    void client_drained_write_cb(struct bufferevent* bev, void* user_arg);
    void server_drained_write_cb(struct bufferevent* bev, void* user_arg);

    void tcp_read_cb(struct bufferevent* bev, void* user_arg);

    void _read_cb(struct bufferevent* bev, void* user_arg, bool loud = 0);

    // TCP event logic for initating side of the tunnel (the "client")
    void client_event_cb(struct bufferevent* bev, short what, void* user_arg);

    // TCP event logic for receiving side of the tunnel (the "server")
    void server_event_cb(struct bufferevent* bev, short what, void* user_arg);

    void tcp_listen_cb(
            struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* src, int socklen, void* user_arg);

    void tcp_err_cb(struct evconnlistener* listener, void* user_arg);

    struct TCPConnection
    {
        TCPConnection(struct bufferevent* _bev, evutil_socket_t _fd, std::shared_ptr<Stream> _s, bool is_initiator = true) :
                bev{_bev}, fd{_fd}, stream{std::move(_s)}, is_tunnel_initiator{is_initiator}
        {
            stream->set_stream_data_cb([this](oxen::quic::Stream& s, bstring_view data) {
                auto sz = data.size();

                if (bev)
                {
                    auto rv = bufferevent_write(bev, data.data(), data.size());
                    log::trace(
                            test_cat,
                            "Stream (id: {}) {} {}B to TCP output buffer!",
                            rv < 0 ? "failed to write" : "successfully wrote",
                            s.stream_id(),
                            sz);

                    // we get the output buffer (it sounds backwards but it isn't)
                    if (evbuffer_get_length(bufferevent_get_output(bev)) >= TCP_HIGHWATER and not s.is_paused())
                    {
                        log::info(
                                test_cat,
                                "TCP output buffer over high-water threshold ({}); pausing stream...",
                                TCP_HIGHWATER);
                        s.pause();

                        if (is_tunnel_initiator)
                            bufferevent_setcb(bev, tcp_read_cb, client_drained_write_cb, client_event_cb, this);
                        else
                            bufferevent_setcb(bev, tcp_read_cb, server_drained_write_cb, server_event_cb, this);

                        bufferevent_setwatermark(bev, EV_WRITE, TCP_LOWWATER, TCP_HIGHWATER);
                    }
                }
                else
                    throw std::runtime_error{"Stream (id: {}) has no socket to write {}B to!"_format(s.stream_id(), sz)};
            });

            stream->set_stream_close_cb([this](Stream&, uint64_t) {
                log::critical(
                        test_cat,
                        "Stream closed cb fired, {}...",
                        bev ? "freeing bufferevent" : "bufferevent already freed");
                if (bev)
                    bufferevent_free(bev);
            });

            stream->set_remote_reset_hooks(
                    opt::remote_stream_reset{nullptr, [this](Stream& s, uint64_t ec) {
                                                 if (is_tunnel_initiator)
                                                     return initiator_stream_reset_cb(bev, s, ec, this);
                                                 else
                                                     return receiver_stream_reset_cb(bev, s, ec, this);
                                             }});

            stream->set_watermark(
                    LOW_WATERMARK,
                    HIGH_WATERMARK,
                    opt::watermark{[this](Stream&) {
                        log::debug(test_cat, "Stream buffer below low-water threshold; enabling TCP read!");
                        bufferevent_enable(bev, EV_READ);
                    }},
                    opt::watermark{[this](Stream&) {
                        log::debug(test_cat, "Stream buffer above high-water threshold; disabling TCP read!");
                        bufferevent_disable(bev, EV_READ);
                    }});
        }

        TCPConnection() = delete;

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection() = default;

        struct bufferevent* bev;
        evutil_socket_t fd;

        std::shared_ptr<Stream> stream;

        bool is_tunnel_initiator{true};
    };

    using tcpconn_hook = std::function<TCPConnection*(struct bufferevent*, evutil_socket_t, oxen::quic::Address src)>;

    class TCPHandle
    {
        using socket_t =
#ifndef _WIN32
                int
#else
                SOCKET
#endif
                ;

        std::shared_ptr<Loop> _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        // The OutboundSession will set up an evconnlistener and set the listening socket address inside ::_bound
        std::optional<Address> _bound = std::nullopt;

        // The InboundSession will set this address to the lokinet-primary-ip to connect to
        std::optional<Address> _connect = std::nullopt;

        socket_t _sock;

        explicit TCPHandle(const std::shared_ptr<Loop>& ev, tcpconn_hook cb, uint16_t p) :
                _ev{ev}, _conn_maker{std::move(cb)}, tunnel_initiator{true}
        {
            assert(_ev);
            assert(tunnel_initiator);

            if (!_conn_maker)
                throw std::logic_error{"TCPSocket construction requires a non-empty receive callback"};

            _init_server(p);
        }

        explicit TCPHandle(const std::shared_ptr<Loop>& ev) : _ev{ev}, tunnel_initiator{false} { assert(_ev); }

      public:
        TCPHandle() = delete;

        tcpconn_hook _conn_maker;

        bool tunnel_initiator{true};

        // The OutboundSession object will hold a server listening on some localhost:port, returning that port to the
        // application for it to make a TCP connection
        static std::shared_ptr<TCPHandle> make_server(const std::shared_ptr<Loop>& ev, tcpconn_hook cb, uint16_t port = 0)
        {
            std::shared_ptr<TCPHandle> h{new TCPHandle(ev, std::move(cb), port)};
            return h;
        }

        // The InboundSession object will hold a client that connects to some application configured
        // lokinet-primary-ip:port every time the OutboundSession opens a new stream over the tunneled connection
        static std::shared_ptr<TCPHandle> make_client(const std::shared_ptr<Loop>& ev)
        {
            std::shared_ptr<TCPHandle> h{new TCPHandle{ev}};
            return h;
        }

        ~TCPHandle()
        {
            _tcp_listener.reset();
            log::info(test_cat, "TCPHandle shut down!");
        }

        uint16_t port() const { return _bound.has_value() ? _bound->port() : 0; }

        // checks _bound has been set by ::make_server(...)
        bool is_bound() const { return _bound.has_value(); }

        // checks _connect has been set by ::connect_to_backend(...)
        bool is_connected() const { return _connect.has_value(); }

        // returns the bind address of the TCP listener
        std::optional<Address> bind() const { return _bound; }

        // returns the socket address of the TCP connection
        std::optional<Address> connect() const { return _connect; }

        std::shared_ptr<TCPConnection> connect_to_backend(std::shared_ptr<Stream> stream, Address addr)
        {
            if (addr.port() == 0)
                throw std::runtime_error{"TCP backend must have valid port on localhost!"};

            log::info(test_cat, "Attempting TCP connection to backend at: {}", addr);
            sockaddr_in _addr = addr.in4();

            struct bufferevent* _bev = bufferevent_socket_new(
                    _ev->loop().get(),
                    -1,
                    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_THREADSAFE /* | BEV_OPT_UNLOCK_CALLBACKS */);

            if (tunnel_initiator != false)
                throw std::runtime_error{"Tunnel server should have tunnel_initiator set to FALSE"};

            auto tcp_conn = std::make_shared<TCPConnection>(_bev, -1, std::move(stream), tunnel_initiator);

            if (bufferevent_socket_connect(_bev, (struct sockaddr*)&_addr, sizeof(_addr)) < 0)
            {
                log::warning(test_cat, "Failed to make bufferevent-based TCP connection!");
                return nullptr;
            }

            bufferevent_setcb(_bev, tcp_read_cb, nullptr, server_event_cb, tcp_conn.get());
            bufferevent_enable(_bev, EV_READ | EV_WRITE);

            // fd is only set after a call to bufferevent_socket_connect
            tcp_conn->fd = bufferevent_getfd(_bev);
            _sock = tcp_conn->fd;

            log::debug(test_cat, "TCP bufferevent has fd: {}", tcp_conn->fd);

            Address temp{};
            if (getsockname(tcp_conn->fd, temp, temp.socklen_ptr()) < 0)
                throw std::runtime_error{
                        "Failed to bind bufferevent: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _connect = temp;

            log::info(test_cat, "TCP bufferevent sock on addr: {}", *_connect);

            return tcp_conn;
        }

      private:
        void _init_client() {}

        void _init_server(uint16_t port)
        {
            sockaddr_in _tcp{};
            _tcp.sin_family = AF_INET;
            _tcp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            _tcp.sin_port = htons(port);

            _tcp_listener = _ev->shared_ptr<struct evconnlistener>(
                    evconnlistener_new_bind(
                            _ev->loop().get(),
                            tcp_listen_cb,
                            this,
                            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE,
                            -1,
                            reinterpret_cast<sockaddr*>(&_tcp),
                            sizeof(sockaddr)),
                    evconnlistener_deleter);

            if (not _tcp_listener)
                throw std::runtime_error{
                        "TCP listener construction failed: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _sock = evconnlistener_get_fd(_tcp_listener.get());

            log::info(test_cat, "TCP server has fd: {}", _sock);

            Address temp{};
            if (getsockname(_sock, temp, temp.socklen_ptr()) < 0)
                throw std::runtime_error{
                        "Failed to bind listener: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _bound = temp;

            evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);

            log::info(test_cat, "TCPHandle set up listener on: {}", *_bound);
        }
    };

    inline void initiator_stream_reset_cb(struct bufferevent* bev, Stream& s, uint64_t ec, void* user_arg)
    {
        auto id = s.stream_id();
        auto msg = "[TUNNEL INITIATOR] Stream (ID:{}) received STREAM_RESET (ec:{}) from remote;"_format(id, ec);

        if (ec == CODE::STOP_NOW)
        {
            return _stop_now_cb(bev, s, user_arg, true);
        }

        // we need to wait to stop reading until the output buffer has drained
        if (bev)
        {
            if (_flush_now_cb(bev, s, user_arg, false))
                return;
        }

        log::critical(test_cat, "{} socket buffers empty; shutting down local stream write", msg);
        s.stop_writing();
    }

    inline void receiver_stream_reset_cb(struct bufferevent* bev, Stream& s, uint64_t ec, void* user_arg)
    {
        auto id = s.stream_id();
        auto msg = "[TUNNEL RECEIVER] Stream (ID:{}) received STREAM_RESET (ec:{}) from remote;"_format(id, ec);

        if (ec == CODE::STOP_NOW)
        {
            return _stop_now_cb(bev, s, user_arg, false);
        }

        if (bev)
        {
            if (_flush_now_cb(bev, s, user_arg, false))
                return;
        }

        msg += "socket buffers empty; ";

        switch (ec)
        {
            case CODE::STOP_READING:
                if (s.is_reading())
                {
                    log::info(test_cat, "{} shutting down stream read!", msg);
                    s.stop_reading();
                }
                else
                {
                    log::info(test_cat, "{} stream read shut down; closing stream!", msg);
                    s.close();
                    bufferevent_free(bev);
                }
            case CODE::STOP_WRITING:
                log::critical(test_cat, "{} shutting down socket write and clearing any pending input buffer data...", msg);

                auto fd = bufferevent_getfd(bev);
                shutdown(fd, SHUT_WR);

                _read_cb(bev, user_arg, true);
        }
    }

    inline bool _flush_now_cb(struct bufferevent* bev, Stream& s, void* user_arg, bool is_initiator)
    {
        auto id = s.stream_id();
        auto whoami = is_initiator ? "[TUNNEL INITIATOR]" : "[TUNNEL RECEIVER]";

        // we need to wait to stop reading until the output buffer has drained
        if (auto outlen = evbuffer_get_length(bufferevent_get_output(bev)); outlen > 0)
        {
            // if we are not the tunnel initiator
            log::critical(
                    test_cat,
                    "{} deferring stream (id: {}) write shutdown until socket output buffer (size: {}B) drains!",
                    whoami,
                    id,
                    outlen);

            // set the close-on-drain cb on the bufferevent and let the stream close usual
            if (is_initiator)
                bufferevent_setcb(bev, tcp_read_cb, tcp_drained_write_free_cb, client_event_cb, user_arg);
            else
                bufferevent_setcb(bev, nullptr, server_drained_write_close_cb, server_event_cb, user_arg);

            bufferevent_setwatermark(bev, EV_WRITE, 0, TCP_HIGHWATER);
            return true;
        }

        // we need to send out all of this data
        if (auto inlen = evbuffer_get_length(bufferevent_get_input(bev)); inlen > 0)
        {
            std::array<uint8_t, 4096> buf{};

            // Load data from input buffer to local buffer
            [[maybe_unused]] auto nwrite = bufferevent_read(bev, buf.data(), buf.size());

            assert(nwrite == inlen);

            log::critical(
                    test_cat,
                    "{} deferring stream (id: {}) close until remaining data (size: {}B) in socket input buffer is flushed!",
                    id,
                    whoami,
                    inlen);
            s.send(ustring{buf.data(), nwrite});
            return true;
        }

        return false;
    }

    inline void _stop_now_cb(struct bufferevent* bev, Stream& s, void* user_arg, bool is_initiator)
    {
        auto id = s.stream_id();
        auto whoami = is_initiator ? "[TUNNEL INITIATOR]" : "[TUNNEL RECEIVER]";

        log::critical(test_cat, "{} REMOTE TCP CONNECTION DIED -- TERMINATING STREAM (ID: {}) IMMEDIATELY", whoami, id);

        if (bev)
        {
            if (auto outlen = evbuffer_get_length(bufferevent_get_output(bev)); outlen > 0)
            {
                log::critical(test_cat, "{} clearing remaining output buffer (size: {}B)...", whoami, outlen);
                bufferevent_disable(bev, EV_READ);
                if (is_initiator)
                    bufferevent_setcb(bev, nullptr, tcp_drained_write_free_cb, client_event_cb, user_arg);
                else
                    bufferevent_setcb(bev, nullptr, server_drained_write_close_cb, server_event_cb, user_arg);
                bufferevent_setwatermark(bev, EV_WRITE, 0, TCP_HIGHWATER);
                // set bev in TCPConnection to nullptr so the stream close cb doesn't free it
                bev = nullptr;
                return;
            }
        }

        if (s.available())
        {
            log::info(test_cat, "{} Closing stream (id: {}) and freeing TCP socket...", whoami, id);
            s.close(CODE::STOP_NOW);
        }
        else
        {
            log::info(test_cat, "{} Stream (id: {}) is already shutting down! Freeing TCP socket...", whoami, id);
        }

        bufferevent_free(bev);
    }

    inline void tcp_drained_write_free_cb(struct bufferevent* bev, void* /* user_arg */)
    {
        if (auto outlen = evbuffer_get_length(bufferevent_get_output(bev)); outlen > 0)
        {
            log::info(test_cat, "TCP outbut buffer has {}B remaining to flush...", outlen);
            return;
        }

        log::info(test_cat, "TCP output buffer drained; freeing bufferevent!");
        bufferevent_free(bev);
    }

    inline void client_drained_write_close_cb(struct bufferevent* bev, void* user_arg)
    {
        if (auto outlen = evbuffer_get_length(bufferevent_get_output(bev)); outlen > 0)
        {
            log::info(test_cat, "[TUNNEL INITIATOR] TCP outbut buffer has {}B remaining to flush...", outlen);
            return;
        }

        bufferevent_setcb(bev, tcp_read_cb, nullptr, client_event_cb, user_arg);
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
        bufferevent_enable(bev, EV_READ);

        log::info(
                test_cat,
                "[TUNNEL INITIATOR] TCP output buffer drained; shutting down socket write and clearing pending input buffer "
                "(if any)...");

        auto fd = bufferevent_getfd(bev);
        shutdown(fd, SHUT_WR);

        _read_cb(bev, user_arg, true);

        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);

        log::info(test_cat, "[TUNNEL INITIATOR] Shutting down stream read!");
        conn->stream->stop_reading();
    }

    inline void server_drained_write_close_cb(struct bufferevent* bev, void* user_arg)
    {
        if (auto outlen = evbuffer_get_length(bufferevent_get_output(bev)); outlen > 0)
        {
            log::info(test_cat, "[TUNNEL RECEIVER] TCP outbut buffer has {}B remaining to flush...", outlen);
            return;
        }

        bufferevent_setcb(bev, tcp_read_cb, nullptr, server_event_cb, user_arg);
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
        bufferevent_enable(bev, EV_READ);

        log::info(
                test_cat,
                "[TUNNEL RECEIVER] TCP output buffer drained; shutting down socket write and clearing pending input buffer "
                "(if any)...");

        auto fd = bufferevent_getfd(bev);
        shutdown(fd, SHUT_WR);

        _read_cb(bev, user_arg, true);

        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);

        log::info(test_cat, "[TUNNEL RECEIVER] Shutting down stream read!");
        conn->stream->stop_reading();
    }

    inline void client_drained_write_cb(struct bufferevent* bev, void* user_arg)
    {
        bufferevent_setcb(bev, tcp_read_cb, nullptr, client_event_cb, user_arg);
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);

        log::info(
                test_cat,
                "[TUNNEL INITIATOR] TCP output buffer below low-water threshold ({}); resuming stream!",
                TCP_LOWWATER);
        conn->stream->resume();
    }

    inline void server_drained_write_cb(struct bufferevent* bev, void* user_arg)
    {
        bufferevent_setcb(bev, tcp_read_cb, nullptr, server_event_cb, user_arg);
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);

        log::info(
                test_cat,
                "[TUNNEL RECEIVER] TCP output buffer below low-water threshold ({}); resuming stream!",
                TCP_LOWWATER);
        conn->stream->resume();
    }

    inline void tcp_read_cb(struct bufferevent* bev, void* user_arg)
    {
        _read_cb(bev, user_arg, false);
    }

    inline void _read_cb(struct bufferevent* bev, void* user_arg, bool loud)
    {
        std::array<uint8_t, 4096> buf{};

        // Load data from input buffer to local buffer
        auto nwrite = bufferevent_read(bev, buf.data(), buf.size());

        if (nwrite > 0)
        {
            auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
            assert(conn);
            auto& stream = conn->stream;
            assert(stream);

            if (loud)
                log::critical(test_cat, "TCP socket received {}B on stream ID:{}", nwrite, stream->stream_id());
            else
                log::trace(test_cat, "TCP socket received {}B on stream ID:{}", nwrite, stream->stream_id());

            stream->send(ustring{buf.data(), nwrite});
        }
        else
        {
            if (loud)
                log::critical(test_cat, "TCP socket has no pending data in input buffer!");
            else
                log::trace(test_cat, "TCP socket has no pending data in input buffer!");
        }
    }

    inline void server_event_cb(struct bufferevent* bev, short what, void* user_arg)
    {
        if (what & BEV_EVENT_CONNECTED)
        {
            log::info(test_cat, "[TUNNEL RECEIVER] TCP connect operation succeeded!");
            return;
        }

        bool close{false};
        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);
        auto& stream = conn->stream;
        auto stream_id = stream->stream_id();

        if (what & BEV_EVENT_ERROR)
        {
            log::critical(
                    test_cat,
                    "[TUNNEL RECEIVER] TCP Connection encountered bufferevent error (msg: {})!",
                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

            log::critical(test_cat, "[TUNNEL RECEIVER] Closing stream (ID:{})...", stream_id);
            // stream->reset_stream(CODE::STOP_NOW);
            stream->close(CODE::STOP_NOW);
            return;
        }

        auto outlen = evbuffer_get_length(bufferevent_get_output(bev));
        auto inlen = evbuffer_get_length(bufferevent_get_input(bev));

        log::critical(test_cat, "[TUNNEL RECEIVER] EVENT: input buffer = {}B, output buffer = {}B", inlen, outlen);

        if (what & BEV_EVENT_EOF)
        {
            if (what & BEV_EVENT_WRITING)
            {
                // backend shut down reading
                log::info(
                        test_cat,
                        "[TUNNEL RECEIVER] Backend TCP stopped reading! Halting stream (ID:{}) write...",
                        stream_id);
                stream->reset_stream(CODE::STOP_WRITING);
            }
            else if (what & BEV_EVENT_READING)
            {
                // backend shut down writing
                // TODO: close here?
                // log::info(test_cat, "[TUNNEL RECEIVER] Backend TCP stopped writing! Halting stream (ID:{}) read...",
                // stream_id);

                log::info(
                        test_cat,
                        "[TUNNEL RECEIVER] Backend TCP stopped writing! Clearing any pending outgoing data (stream id: {}) "
                        "and halting stream read...",
                        stream_id);

                // log::info(
                //         test_cat,
                //         "[TUNNEL RECEIVER] Backend TCP stopped writing! Clearing (stream id: {}) any pending outgoing data
                //         and freeing socket on write termination!", stream_id);
                // auto fd = bufferevent_getfd(bev);
                // shutdown(fd, SHUT_WR);

                // // flush any pending data
                _read_cb(bev, user_arg, true);

                stream->stop_sending(CODE::STOP_WRITING);

                // stream->reset_stream(CODE::STOP_WRITING);
                // bufferevent_disable(bev, EV_READ);
                // bufferevent_setcb(bev, nullptr, tcp_drained_write_free_cb, server_event_cb, user_arg);
                // bufferevent_setwatermark(bev, EV_WRITE, 0, TCP_HIGHWATER);

                // close = true;
                // stream->stop_reading();

                // log::info(test_cat, "[TUNNEL RECEIVER] shutting down stream write...");
            }
            else
            {
                // remote closed connection
                log::info(test_cat, "[TUNNEL RECEIVER] TCP Connection EOF!");
                close = true;
            }
        }
        if (close)
        {
            // log::critical(test_cat, "[TUNNEL RECEIVER] Closing stream (ID:{})...", stream_id);
            // stream->close(CODE::STOP_NOW);
            log::critical(test_cat, "[TUNNEL RECEIVER] Closing stream (ID:{}) via read shutdown...", stream_id);
            stream->stop_reading();
        }
    }

    inline void client_event_cb(struct bufferevent* bev, short what, void* user_arg)
    {
        if (what & BEV_EVENT_CONNECTED)
        {
            log::info(test_cat, "[TUNNEL INITIATOR] TCP connect operation succeeded!");
            return;
        }

        bool close{false};
        auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
        assert(conn);
        auto& stream = conn->stream;
        auto stream_id = stream->stream_id();

        if (what & BEV_EVENT_ERROR)
        {
            log::critical(
                    test_cat,
                    "[TUNNEL INITIATOR] TCP Connection encountered bufferevent error (msg: {})!",
                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            close = true;
        }

        auto outlen = evbuffer_get_length(bufferevent_get_output(bev));
        auto inlen = evbuffer_get_length(bufferevent_get_input(bev));

        log::critical(test_cat, "[TUNNEL INITIATOR] EVENT: input buffer = {}B, output buffer = {}B", inlen, outlen);

        if (what & BEV_EVENT_EOF)
        {
            if (what & BEV_EVENT_WRITING)
            {
                // backend shut down reading
                log::info(
                        test_cat,
                        "[TUNNEL INITIATOR] Backend TCP stopped reading! Halting stream (ID:{}) write...",
                        stream_id);
                stream->reset_stream(CODE::STOP_WRITING);
                // log::info(test_cat, "Backend TCP stopped reading! Halting stream (ID:{}) read...", stream_id);
                // stream->stop_reading();
            }
            else if (what & BEV_EVENT_READING)
            {
                // backend shut down writing
                log::info(
                        test_cat,
                        "[TUNNEL INITIATOR] Backend TCP stopped writing! Clearing any pending outgoing data and halting "
                        "stream (ID:{}) write...",
                        stream_id);

                // flush any pending data
                _read_cb(bev, user_arg, true);

                stream->reset_stream(CODE::STOP_WRITING);

                // log::info(test_cat, "[TUNNEL INITIATOR] Backend TCP stopped writing! Halting stream (ID:{}) read...",
                // stream_id); stream->stop_reading();
            }
            else
            {
                // remote closed connection
                log::info(test_cat, "[TUNNEL INITIATOR] TCP Connection EOF!");
                close = true;
            }
        }
        if (close)
        {
            // log::critical(test_cat, "[TUNNEL INITIATOR] Closing stream (ID:{})...", stream_id);
            // stream->close();
            log::critical(test_cat, "[TUNNEL INITIATOR] Closing stream (ID:{}) via read shutdown...", stream_id);
            stream->stop_reading();
        }
    }

    inline void tcp_listen_cb(
            struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* src, int socklen, void* user_arg)
    {
        oxen::quic::Address source{src, static_cast<socklen_t>(socklen)};
        log::info(test_cat, "TCP CONNECTION ESTABLISHED -- SRC: {}", source);

        auto* b = evconnlistener_get_base(listener);
        auto* _bev = bufferevent_socket_new(
                b,
                fd,
                BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_THREADSAFE /* | BEV_OPT_UNLOCK_CALLBACKS */);

        auto* handle = reinterpret_cast<TCPHandle*>(user_arg);
        assert(handle);

        // make TCPConnection here!
        auto* conn = handle->_conn_maker(_bev, fd, std::move(source));
        auto stream = conn->stream;

        bufferevent_setcb(_bev, tcp_read_cb, nullptr, client_event_cb, conn);
        bufferevent_enable(_bev, EV_READ | EV_WRITE);
    }

    inline void tcp_err_cb(struct evconnlistener* /* e */, void* user_arg)
    {
        int ec = EVUTIL_SOCKET_ERROR();
        log::critical(test_cat, "TCP LISTENER RECEIVED ERROR CODE {}: {}", ec, evutil_socket_error_to_string(ec));

        [[maybe_unused]] auto* handle = reinterpret_cast<TCPHandle*>(user_arg);
        assert(handle);

        // DISCUSS: close everything here?
    }
}  //  namespace oxen::quic
