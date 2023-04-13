#pragma once

#include "stream.hpp"
#include "endpoint.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw/async.h>
#include <uvw/timer.h>
#include <uvw/poll.h>

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
            int
            init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

            ngtcp2_pkt_info pkt_info{};

        public:
            //  Create and establish a new connection from local client to remote server
            //      ep: tunnel object managing this connection
            //      scid: source/local ("primary") CID used for this connection (usually random)
            //      path: network path to reach remote server
            //      tunnel_port: destination port to tunnel to at remote end
            Connection(
                Tunnel& ep, const ngtcp2_cid& scid, const Path& path, uint16_t tunnel_port);

            //  Construct and initialize a new incoming connection from remote client to local server
            //      ep: tunnel objec tmanaging this connection
            //      scid: local ("primary") CID usd for this connection (usually random)
            //      header: packet header used to initialize connection
            //      path: network path used to reach remote client
            Connection(
                Tunnel& ep, const ngtcp2_cid& scid, ngtcp2_pkt_hd& hdr, const Path& path);

            ~Connection();

            // Callbacks to be invoked if set
            std::function<void(Connection&)> on_stream_available;
            std::function<void(Connection&)> on_closing;            // clear immediately after use

            int
            init_gnutls(Client& client);

            int
            init_gnutls(Server& server);

            int
            get_streams_available();

            const uint64_t 
            timestamp(void);

            static ngtcp2_cid
            random(size_t size = NGTCP2_MAX_CIDLEN);

            std::unique_ptr<ngtcp2_conn> conn;
            int conn_fd;
            struct sockaddr_storage local_addr;
            socklen_t local_addrlen;
            gnutls_session_t session;
            gnutls_certificate_credentials_t cred;

            uint16_t client_tunnel_port = 0;

            // Buffer used to store non-stream connection data
            //  ex: initial transport params
            bstring conn_buffer;

            Tunnel& tun_endpoint;

            ngtcp2_cid source_cid;
            ngtcp2_cid dest_cid;

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
