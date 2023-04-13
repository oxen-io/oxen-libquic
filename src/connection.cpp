#include "connection.hpp"
#include "ngtcp2/ngtcp2.h"

#include <arpa/inet.h>
#include <cassert>
#include <cstdint>
#include <exception>
#include <stdexcept>


namespace oxen::quic
{
    using namespace std::literals;

    int 
    hook_func(gnutls_session_t session, unsigned int htype, unsigned when, 
            unsigned int incoming, const gnutls_datum_t *msg) 
    {
		(void)session;
		(void)htype;
		(void)when;
		(void)incoming;
		(void)msg;
		/* we could save session data here */

		return 0;
	}

    int 
    numeric_host_family(const char *hostname, int family) 
    {
		uint8_t dst[sizeof(struct in6_addr)];
		return inet_pton(family, hostname, dst) == 1;
	}

	int 
    numeric_host(const char *hostname) 
    {
		return numeric_host_family(hostname, AF_INET) ||
			numeric_host_family(hostname, AF_INET6);
    }

    void 
    log_printer(void *user_data, const char *fmt, ...) 
    {
        va_list ap;
        (void)user_data;

        va_start(ap, fmt);
        fprintf(stderr, fmt, ap);
        va_end(ap);

        fprintf(stderr, "\n");
    }

    void 
    rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) 
    {
        (void)rand_ctx;

        (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
    }

    int 
    get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, 
                            size_t cidlen, void *user_data) 
    {
        (void)conn;
        (void)user_data;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        cid->datalen = cidlen;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        return 0;
    }

    int 
    extend_max_local_streams_bidi(ngtcp2_conn* _conn, uint64_t max_streams, void* user_data) 
    {
    #ifdef MESSAGE
        auto& conn = *static_cast<Connection*>(user_data);
        assert(_conn == conn);

        if (conn.on_stream_available)
        {
            if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn.conn.get()); remaining > 0)
                conn.on_stream_available(conn);
        }
    #else
        (void)_conn;
        (void)max_streams;
        (void)user_data;
    #endif
        return 0;
    }


    const uint64_t
    Connection::timestamp()
    {
        struct timespec tp;

        int rv = clock_gettime(CLOCK_MONOTONIC, &tp);

        if (rv != 0) {
            fprintf(stderr, "clock_gettime: %s\n", strerror(rv));
            exit(EXIT_FAILURE);
        }

        return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
    }


    ngtcp2_cid
    Connection::random(size_t size)
    {
        ngtcp2_cid cid;
        cid.datalen = std::min(size, static_cast<size_t>(NGTCP2_MAX_CIDLEN));
        std::generate(cid.data, (cid.data + cid.datalen), rand);
        return cid;
    }


    int
    Connection::init_gnutls(Client& client)
    {
        int rv = gnutls_certificate_allocate_credentials(&cred);

        if (rv == 0)
            rv = gnutls_certificate_set_x509_system_trust(cred);
        if (rv < 0) {
            fprintf(stderr, "cred init failed: %d: %s\n", rv, gnutls_strerror(rv));
            return -1;
        }

        rv = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                        GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
            return -1;
        }

        if (ngtcp2_crypto_gnutls_configure_client_session(session) != 0) {
            fprintf(stderr, "ngtcp2_crypto_gnutls_configure_client_session failed\n");
            return -1;
        }

        rv = gnutls_priority_set_direct(session, priority, NULL);
        if (rv != 0) {
            fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
                                            GNUTLS_HOOK_POST, hook_func);

        gnutls_session_set_ptr(session, conn.get());

        rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

        if (rv != 0) {
            fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

        if (!numeric_host(REMOTE_HOST))
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, REMOTE_HOST,
                                    strlen(REMOTE_HOST));
        else
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",
                                    strlen("localhost"));

        return 0;
    }

    int
    Connection::init_gnutls(Server& server)
    {
        int rv = gnutls_certificate_allocate_credentials(&cred);

        if (rv == 0)
            rv = gnutls_certificate_set_x509_system_trust(cred);
        if (rv < 0) {
            fprintf(stderr, "cred init failed: %d: %s\n", rv, gnutls_strerror(rv));
            return -1;
        }

        rv = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                        GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
            return -1;
        }

        if (ngtcp2_crypto_gnutls_configure_server_session(session) != 0) {
            fprintf(stderr, "ngtcp2_crypto_gnutls_configure_server_session failed\n");
            return -1;
        }

        rv = gnutls_priority_set_direct(session, priority, NULL);
        if (rv != 0) {
            fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
                                            GNUTLS_HOOK_POST, hook_func);

        gnutls_session_set_ptr(session, conn.get());

        rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

        if (rv != 0) {
            fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
            return -1;
        }

        gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

        if (!numeric_host(REMOTE_HOST))
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, REMOTE_HOST,
                                    strlen(REMOTE_HOST));
        else
            gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",
                                    strlen("localhost"));

        return 0;
    }

    int
    Connection::get_streams_available()
    {
        uint64_t open = ngtcp2_conn_get_streams_bidi_left(conn.get());
        if (open > std::numeric_limits<uint64_t>::max())
            return -1;
        return static_cast<int>(open);
    }

    int
    Connection::init(ngtcp2_settings &settings, ngtcp2_transport_params &params, 
                    ngtcp2_callbacks &callbacks)
    {
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
        callbacks.rand = rand_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

        ngtcp2_cid dcid, scid;
        
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0) 
        {
            fprintf(stderr, "Error: gnutls_rnd failed\n");
            return -1;
        }

        scid.datalen = 8;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0) 
        {
            fprintf(stderr, "Error: gnutls_rnd failed\n");
            return -1;
        }

        ngtcp2_settings_default(&settings);

        settings.initial_ts = timestamp();
        settings.log_printf = log_printer;
        
        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 1024 * 1024;
        // Max concurrent streams supported on one connection
        params.initial_max_stream_data_uni = 0;
        params.initial_max_streams_bidi = 32;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to us)
        params.initial_max_stream_data_bidi_local = 64 * 1024;
        params.initial_max_stream_data_bidi_remote = 64 * 1024;

        return 0;
    }


    //  client conn
    Connection::Connection( 
        Tunnel& ep, const ngtcp2_cid& scid, const Path& path, uint16_t tunnel_port)
        : tun_endpoint{ep}, client_tunnel_port{tunnel_port}, source_cid{scid}, dest_cid{Connection::random()}, path{path}
    {
        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks;
        ngtcp2_conn* connptr;
        
        if (auto rv = init(settings, params, callbacks); rv != 0)
            fprintf(stderr, "Error: Server-based connection not created\n");

        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

        int rv = ngtcp2_conn_client_new(
            &connptr, 
            &dest_cid, 
            &source_cid, 
            path, 
            NGTCP2_PROTO_VER_V1,
            &callbacks,
            &settings,
            &params, 
            nullptr, 
            this);

        if (rv != 0) {
            throw std::runtime_error{"Failed to initialize client connection to server: "s + ngtcp2_strerror(rv)};
        }
        conn.reset(connptr);

        ngtcp2_conn_set_tls_native_handle(conn.get(), session);
    }


    //  server conn
    Connection::Connection(
        Tunnel& ep, const ngtcp2_cid& cid, ngtcp2_pkt_hd& hdr, const Path& path)
        : tun_endpoint{ep}, source_cid{cid}, dest_cid{hdr.dcid}, path{path}
    {
        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks;
        ngtcp2_cid dcid, scid;
        ngtcp2_conn* connptr;
        
        if (auto rv = init(settings, params, callbacks); rv != 0)
            fprintf(stderr, "Error: Server-based connection not created\n");

        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

        int rv = ngtcp2_conn_server_new(&connptr, &dcid, &scid, path, NGTCP2_PROTO_VER_V1,
                                        &callbacks, &settings, &params, nullptr, this);

        if (rv != 0) {
            throw std::runtime_error{"Failed to initialize server connection to client: "s + ngtcp2_strerror(rv)};
        }
        conn.reset(connptr);

        ngtcp2_conn_set_tls_native_handle(conn.get(), session);
    }

}   // namespace oxen::quic
