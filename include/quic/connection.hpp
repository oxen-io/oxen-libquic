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
#include "gnutls_crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    /*
        TODO:
        - tls creds and session?
        - user config settings (for debugging)
        - closing connection through conn interface?
            - current close mechanism lives in endpoint

        - tests
            - fix 002-007
            - stream test cases for switching # of streams mid connection

        - make retransmit timer private
        - anything touched by network and endpoint is public
            - make everything private
            - anything the user calls are public overrides in connection_interface
        
    */

    class connection_interface
    {
      public:
        virtual std::shared_ptr<Stream> get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr) = 0;

        virtual ConnectionID get_conn_id() = 0;
    };

    class Connection : public connection_interface, public std::enable_shared_from_this<Connection>
    {
      public:
        // Construct and initialize a new inbound/outbound connection to/from a remote
        //      ep: owning endpoints
        //      scid: local ("primary") CID used for this connection (random for outgoing)
        //		dcid: remote CID used for this connection
        //      path: network path used to reach remote client
        //		handle: udp handle dedicated to local address
        //		creds: relevant tls information per connection
        //		u_config: user configuration values passed in struct
        //      dir: enum specifying configuration detailts for client vs. server
        //		hdr: optional parameter to pass to ngtcp2 for server specific details
        Connection(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<uv_udp_t> handle,
                std::shared_ptr<TLSCreds> creds,
                config_t u_config,
                Direction dir,
                ngtcp2_pkt_hd* hdr = nullptr);
        ~Connection();

        static std::shared_ptr<Connection> make_conn(
                Endpoint& ep,
                const ConnectionID& scid,
                const ConnectionID& dcid,
                const Path& path,
                std::shared_ptr<uv_udp_t> handle,
                std::shared_ptr<TLSCreds> creds,
                config_t u_config,
                Direction dir,
                ngtcp2_pkt_hd* hdr = nullptr);

        // Returns a pointer to the owning endpoint, else nullptr
        Endpoint* endpoint();
        const Endpoint* endpoint() const;

        void io_ready();

        const GNUTLSSession* get_session()
        { return dynamic_cast<GNUTLSSession*>(tls_session.get()); };

        std::shared_ptr<Stream> get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr) override;

        ConnectionID get_conn_id() override
        { return _source_cid; }

        Direction direction()
        { return dir; }

        bool is_closing()
        { return closing; }
        bool is_draining()
        { return draining; }
        const ConnectionID scid()
        { return _source_cid; }
        const ConnectionID dcid()
        { return _dest_cid; }
        const Path path()
        { return _path; }

        std::function<void(Connection&)> on_closing;  // clear immediately after use

      private:
        std::shared_ptr<uv_udp_t> udp_handle;
        config_t user_config;
        Direction dir;
        Endpoint& _endpoint;
        const ConnectionID _source_cid;
        ConnectionID _dest_cid;
        Path _path;
        const Address _local;
        const Address _remote;

        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

        void setup_tls_session(bool is_client);

        std::shared_ptr<TLSCreds> tls_creds;
        std::unique_ptr<TLSSession> tls_session;

        std::shared_ptr<uvw::timer_handle> retransmit_timer;


        void on_io_ready();

        struct pkt_tx_timer_updater;
        bool send(pkt_tx_timer_updater* pkt_updater = nullptr);

        void flush_streams(uint64_t ts);

        std::array<uint8_t, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        size_t n_packets = 0;
        uint8_t* send_buffer_pos = send_buffer.data();


        void schedule_retransmit(uint64_t ts = 0);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;


        int get_streams_available();

        bool draining = false;
        bool closing = false;

        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        ngtcp2_ccerr last_error;

        std::shared_ptr<uvw::async_handle> io_trigger;
      
      public:
        // Buffer used to store non-stream connection data
        //  ex: initial transport params
        bstring conn_buffer;
        // these are public so ngtcp2 can access them from callbacks
        int stream_opened(int64_t id);
        int stream_ack(int64_t id, size_t size);
        int stream_receive(int64_t id, bstring_view data, bool fin);
        void stream_closed(int64_t id, uint64_t app_code);
        void check_pending_streams(
                int available, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);
        
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
