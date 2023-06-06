#pragma once

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <uvw.hpp>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint;
    class Stream;
    class Server;
    class Client;
    class Handler;

    class Connection
    {
      private:
        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

        send_buffer_t send_buffer{};
        size_t send_buffer_size = 0;
        size_t n_packets = 0;
        ngtcp2_pkt_info pkt_info{};

      public:
        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;
        // ngtcp2_crypto_conn_ref conn_ref;
        std::shared_ptr<TLSContext> tls_context;
        std::shared_ptr<uvw::UDPHandle> udp_handle;

        Address local;
        Address remote;

        std::shared_ptr<uvw::TimerHandle> retransmit_timer;

        // Create and establish a new connection from local client to remote server
        //      ep: tunnel object managing this connection
        //      scid: source/local ("primary") CID used for this connection (usually random)
        //      path: network path to reach remote server
        //      tunnel_port: destination port to tunnel to at remote end
        Connection(
                Client& client,
                std::shared_ptr<Handler> ep,
                const ConnectionID& scid,
                const Path& path,
                std::shared_ptr<uvw::UDPHandle> handle);

        // Construct and initialize a new incoming connection from remote client to local server
        //      ep: tunnel objec tmanaging this connection
        //      scid: local ("primary") CID usd for this connection (usually random)
        //      header: packet header used to initialize connection
        //      path: network path used to reach remote client
        Connection(
                Server& server,
                std::shared_ptr<Handler> ep,
                const ConnectionID& scid,
                ngtcp2_pkt_hd& hdr,
                const Path& path,
                std::shared_ptr<TLSContext> ctx);

        ~Connection();

        // Callbacks to be invoked if set
        std::function<void(Connection&)> on_closing;  // clear immediately after use

        // change to check_pending_streams, do not create after while loop
        void check_pending_streams(
                int available, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<Stream> get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        void on_io_ready();

        io_result send(uint64_t ts);

        void flush_streams();

        void io_ready();

        /// Returns a pointer to the owning Server, if this is a Server connection, nullptr
        /// otherwise.
        Server* server();
        const Server* server() const;

        /// Returns a pointer to the owning Client, if this is a Client connection, nullptr
        /// otherwise.
        Client* client();
        const Client* client() const;

        void schedule_retransmit();

        int init_gnutls(Client& client);

        int init_gnutls(Server& server);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;

        int stream_opened(int64_t id);

        int stream_ack(int64_t id, size_t size);

        int stream_receive(int64_t id, bstring_view data, bool fin);

        void stream_closed(int64_t id, uint64_t app_code);

        int get_streams_available();

        int recv_initial_crypto(std::basic_string_view<uint8_t> data);

        // Buffer used to store non-stream connection data
        //  ex: initial transport params
        bstring conn_buffer;

        std::shared_ptr<Handler> quic_manager;
        Endpoint& endpoint;

        const ConnectionID source_cid;
        ConnectionID dest_cid;

        bool draining = false;
        bool closing = false;

        Path path;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        ngtcp2_connection_close_error last_error;

        std::shared_ptr<uvw::AsyncHandle> io_trigger;

        // pass Connection as ngtcp2_conn object
        operator const ngtcp2_conn*() const { return conn.get(); }
        operator ngtcp2_conn*() { return conn.get(); }
        operator ngtcp2_conn&() { return *conn.get(); }
    };

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref);

        void log_printer(void* user_data, const char* fmt, ...);
    }

}  // namespace oxen::quic
