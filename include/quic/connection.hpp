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

        std::shared_ptr<uv_udp_t> udp_handle;

        config_t user_config;

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

        void setup_tls_session(bool is_client);

      public:
        std::shared_ptr<TLSCreds> tls_creds;
        std::unique_ptr<TLSSession> tls_session;

        Address local;
        Address remote;

        std::shared_ptr<uvw::timer_handle> retransmit_timer;

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
                std::shared_ptr<uv_udp_t> handle,
                config_t u_config);

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
                std::shared_ptr<TLSCreds> creds,
                config_t u_config);

        ~Connection();

        // Callbacks to be invoked if set
        std::function<void(Connection&)> on_closing;  // clear immediately after use

        // change to check_pending_streams, do not create after while loop
        void check_pending_streams(
                int available, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        std::shared_ptr<Stream> get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

        void on_io_ready();

        struct pkt_tx_timer_updater;
        bool send(pkt_tx_timer_updater* pkt_updater = nullptr);

        void flush_streams(uint64_t ts);

        void io_ready();

        std::array<uint8_t, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        size_t n_packets = 0;
        uint8_t* send_buffer_pos = send_buffer.data();

        /// Returns a pointer to the owning Server, if this is a Server connection, nullptr
        /// otherwise.
        Server* server();
        const Server* server() const;

        /// Returns a pointer to the owning Client, if this is a Client connection, nullptr
        /// otherwise.
        Client* client();
        const Client* client() const;

        void schedule_retransmit(uint64_t ts = 0);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;

        int stream_opened(int64_t id);

        int stream_ack(int64_t id, size_t size);

        int stream_receive(int64_t id, bstring_view data, bool fin);

        void stream_closed(int64_t id, uint64_t app_code);

        int get_streams_available();

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

        ngtcp2_ccerr last_error;

        std::shared_ptr<uvw::async_handle> io_trigger;

        // pass Connection as ngtcp2_conn object
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator const T*() const
        {
            return conn.get();
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator T*()
        {
            return conn.get();
        }
    };

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref);

        void log_printer(void* user_data, const char* fmt, ...);
    }

}  // namespace oxen::quic
