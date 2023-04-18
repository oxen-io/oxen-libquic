#pragma once

#include "stream.hpp"
#include "endpoint.hpp"
#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <uvw/async.h>
#include <uvw/timer.h>
#include <uvw/poll.h>

#include <map>
#include <functional>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <cstdio>


namespace oxen::quic
{
    class Endpoint;
    class Server;
    class Client;

    class Connection : public std::enable_shared_from_this<Connection>
    {
        private:

            struct connection_deleter
            {
                inline void
                operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
            };

            int
            init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

            std::array<std::byte, NGTCP2_MAX_UDP_PAYLOAD_SIZE> send_buffer{};
            size_t send_buffer_size = 0;
            ngtcp2_pkt_info pkt_info{};

        public:
            //  Create and establish a new connection from local client to remote server
            //      ep: tunnel object managing this connection
            //      scid: source/local ("primary") CID used for this connection (usually random)
            //      path: network path to reach remote server
            //      tunnel_port: destination port to tunnel to at remote end
            Connection(
                Client& client, Tunnel& ep, const ConnectionID& scid, const Path& path, uint16_t tunnel_port);

            //  Construct and initialize a new incoming connection from remote client to local server
            //      ep: tunnel objec tmanaging this connection
            //      scid: local ("primary") CID usd for this connection (usually random)
            //      header: packet header used to initialize connection
            //      path: network path used to reach remote client
            Connection(
                Server& server, Tunnel& ep, const ConnectionID& scid, ngtcp2_pkt_hd& hdr, const Path& path);

            ~Connection();

            // Callbacks to be invoked if set
            std::function<void(Connection&)> on_stream_available;
            std::function<void(Connection&)> on_closing;            // clear immediately after use

            const std::shared_ptr<Stream>&
            open_stream(data_callback_t data_cb, close_callback_t close_cb);

            void
            on_io_ready();

            io_result
            send();

            void
            flush_streams();

            void
            io_ready();

            void
            schedule_retransmit();

            Server*
            server();

            Client*
            client();

            int
            init_gnutls(Client& client);

            int
            init_gnutls(Server& server);

            const std::shared_ptr<Stream>&
            get_stream(int64_t ID) const;

            int
            stream_opened(int64_t id);

            int
            stream_ack(int64_t id, size_t size);

            int
            stream_receive(int64_t id, bstring data, bool fin);

            void
            stream_closed(int64_t id, uint64_t app_code);

            int
            get_streams_available();

            int
            recv_initial_crypto(std::basic_string_view<uint8_t> data);

            std::unique_ptr<ngtcp2_conn, connection_deleter> conn;
            ngtcp2_crypto_conn_ref conn_ref;
            int conn_fd;
            std::byte pkt_type;
            struct sockaddr_storage local_addr;
            socklen_t local_addrlen;
            gnutls_session_t session;
            gnutls_certificate_credentials_t cred;
            std::shared_ptr<uvw::TimerHandle> retransmit_timer;

            uint16_t client_tunnel_port = 0;

            // Buffer used to store non-stream connection data
            //  ex: initial transport params
            bstring conn_buffer;

            Tunnel& tun_endpoint;
            std::unique_ptr<Endpoint> endpoint;

            const ConnectionID source_cid;
            ConnectionID dest_cid;

            bool draining = false;
            bool closing = false;

            Path path;

            std::map<int64_t, std::shared_ptr<Stream>> streams;

            ngtcp2_connection_close_error last_error;

            std::shared_ptr<uvw::AsyncHandle> io_trigger;
            
            // pass Connection as ngtcp2_conn object
            operator const ngtcp2_conn*() const
            { return conn.get(); }
            operator ngtcp2_conn*()
            { return conn.get(); }

    };

}   // namespace oxen::quic
