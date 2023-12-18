#include "connection.hpp"
#include "gnutls_crypto.hpp"

namespace oxen::quic
{
    extern "C"
    {
        int gnutls_callback_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            auto* tls_session = get_session_from_gnutls(session);
            // No need to assert the ptr is set here, it's checked in the function before returning.
            // Instead, check that the return matches expected
            assert(tls_session->get_session() == session);

            return tls_session->do_tls_callback(session, htype, when, incoming, msg);
        }

        int gnutls_post_handshake(gnutls_session_t session)
        {
            auto* tls_session = get_session_from_gnutls(session);
            // Same notes on the assert as in gnutls_callback_wrapper above
            assert(tls_session->get_session() == session);
            (void)tls_session;

            // DISCUSS: currently, servers request certificates from all clients. If we wanted to
            // request based on some initial connection information (alpns, etc), we could call
            // gnutls_certificate_server_set_request here instead on the gnutls_session_t object

            return 0;
        }
    }

    GNUTLSSession* get_session_from_gnutls(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
        assert(tls_session);
        return tls_session;
    }

    Connection* get_connection_from_gnutls(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        return conn;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    void GNUTLSSession::set_tls_hook_functions()
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        // gnutls_handshake_set_post_client_hello_function(session, gnutls_post_handshake);
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, gnutls_callback_wrapper);
    }

    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            bool is_client,
            const std::vector<std::string>& alpns,
            std::optional<gnutls_key> expected_key) :
            creds{creds}, is_client{is_client}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        if (expected_key)
            _expected_remote_key = *expected_key;

        auto direction_string = (is_client) ? "Client"s : "Server"s;
        log::trace(log_cat, "Creating {} GNUTLSSession", direction_string);

        uint32_t init_flags = is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;

        // DISCUSS: we actually don't want to do this if the requested certificate is expecting
        // x509 (see gnutls_creds.cpp::cert_retrieve_callback_gnutls function body)
        if (creds.using_raw_pk)
        {
            log::debug(log_cat, "Setting GNUTLS_ENABLE_RAWPK flag on gnutls_init");
            init_flags |= GNUTLS_ENABLE_RAWPK;
        }

        if (auto rv = gnutls_init(&session, init_flags); rv < 0)
        {
            log::error(log_cat, "{} gnutls_init failed: {}", direction_string, gnutls_strerror(rv));
            throw std::runtime_error("{} gnutls_init failed"_format(direction_string));
        }

        if (creds.using_raw_pk)
        {
            if (auto rv = gnutls_priority_set(session, creds.priority_cache); rv < 0)
            {
                log::error(log_cat, "gnutls_priority_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_priority_set failed");
            }
        }
        else if (auto rv = gnutls_set_default_priority(session); rv < 0)
        {
            log::error(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_set_default_priority failed");
        }

        if (alpns.size())
        {
            std::vector<gnutls_datum_t> allowed_alpns;
            for (auto& s : alpns)
            {
                log::trace(log_cat, "GNUTLS adding \"{}\" to {} ALPNs", s, direction_string);
                allowed_alpns.emplace_back(gnutls_datum_t{
                        reinterpret_cast<uint8_t*>(const_cast<char*>(s.data())), static_cast<uint32_t>(s.size())});
            }

            if (auto rv =
                        gnutls_alpn_set_protocols(session, &(allowed_alpns[0]), allowed_alpns.size(), GNUTLS_ALPN_MANDATORY);
                rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }
        }
        else  // set default, mandatory ALPN string
        {
            if (auto rv = gnutls_alpn_set_protocols(session, &GNUTLS_DEFAULT_ALPN, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }
        }

        // server always requests cert from client
        // NOTE: I had removed the check on creds.using_raw_pk to test the server requesting certs every time,
        // but not requiring them
        log::debug(
                log_cat,
                "[GNUTLS SESSION] Local ({}) cert type:{} \t Peer expecting cert type:{}",
                is_client ? "CLIENT" : "SERVER",
                get_cert_type(session, GNUTLS_CTYPE_OURS),
                get_cert_type(session, GNUTLS_CTYPE_PEERS));
        if (not is_client)
        {
            gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
        }

        if (is_client)
        {
            log::trace(log_cat, "gnutls configuring client session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }
        else
        {
            log::trace(log_cat, "gnutls configuring server session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds.cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_credentials_set failed");
        }

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (is_client)
        {
            if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            {
                log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_server_name_set failed");
            }
        }

        set_tls_hook_functions();
    }

    ustring_view GNUTLSSession::selected_alpn()
    {
        gnutls_datum_t proto;

        if (auto rv = gnutls_alpn_get_selected_protocol(session, &proto); rv < 0)
        {
            auto err = fmt::format("{} called, but ALPN negotiation incomplete.", __PRETTY_FUNCTION__);
            throw std::logic_error(err);
        }

        return proto.size ? ustring_view{proto.data, proto.size} : ""_usv;
    }

    int GNUTLSSession::do_tls_callback(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& hook = (is_client) ? creds.client_tls_hook : creds.server_tls_hook;

        if (hook)
        {
            if (hook.htype == htype && hook.when == when && hook.incoming == incoming)
            {
                log::debug(log_cat, "Calling {} tls policy cb", (is_client) ? "client" : "server");
                return hook(session, htype, when, incoming, msg);
            }
        }

        log::trace(log_cat, "No TLS hook to call!");
        return 0;
    }

    int GNUTLSSession::do_post_handshake(gnutls_session_t session)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        (void)session;
        return 0;
    }

    //  In our new cert verification scheme, the logic proceeds as follows.
    //
    //  - Upon every connection, the local endpoint will request certificates from ALL peers
    //  - IF: the local endpoint provided a key_verify callback
    //      - IF: the peer provides a certificate:
    //          - If the certificate is accepted, then the connection is allowed and the
    //            connection is marked as "validated"
    //          - If the certificate is rejected, then the connection is refused
    //        ELSE:
    //          - The connection is refused
    //    ELSE: the remote pubkey is compared against the pubkey in the address upon connection
    //      - If the pubkey matches, then the connection is allowed and the connection is
    //        marked as "validated"
    //      - If the pubkeys don't match, then the connection is refused
    //
    //  Return values:
    //       true: The connection is accepted and marked "validated"
    //       false: The connection is refused
    //
    bool GNUTLSSession::validate_remote_key()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(creds.using_raw_pk);

        const auto local_name = is_client ? "CLIENT" : "SERVER";
        bool success = false;

        log::debug(
                log_cat,
                "Local ({}) cert type:{} \t Peer expecting cert type:{}",
                local_name,
                get_cert_type(session, GNUTLS_CTYPE_OURS),
                get_cert_type(session, GNUTLS_CTYPE_PEERS));

        auto cert_type = gnutls_certificate_type_get2(session, GNUTLS_CTYPE_PEERS);

        // this function is only for raw pubkey mode, and should not be called otherwise
        if (cert_type != GNUTLS_CRT_RAWPK)
        {
            log::error(
                    log_cat,
                    "{} called, but remote cert type is not raw pubkey (type: {}).",
                    __PRETTY_FUNCTION__,
                    translate_cert_type(cert_type));
            return success;
        }

        uint32_t cert_list_size = 0;
        const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

        // The peer did not return a certificate
        if (cert_list_size == 0)
        {
            log::debug(log_cat, "Quic {} called {}, but peers cert list is empty.", local_name, __PRETTY_FUNCTION__);
            return success;
        }

        if (cert_list_size != 1)
        {
            log::debug(
                    log_cat,
                    "Quic {} received peers cert list with more than one entry; choosing first item and proceeding...",
                    local_name);
        }

        const auto* cert_data = cert_list[0].data + CERT_HEADER_SIZE;
        auto cert_size = cert_list[0].size - CERT_HEADER_SIZE;

        log::debug(
                log_cat,
                "Quic {} validating pubkey \"cert\" of len {}B:\n{}\n",
                local_name,
                cert_size,
                buffer_printer{cert_data, cert_size});

        // pubkey comes as 12 bytes header + 32 bytes key
        _remote_key.write(cert_data, cert_size);

        if (is_client)
        {  // Client does validation through a remote pubkey provided when calling endpoint::connect
            success = _remote_key == _expected_remote_key;

            log::debug(
                    log_cat,
                    "Quic {} {}successfully validated remote key! {} connection",
                    local_name,
                    success ? "" : "un",
                    success ? "accepting" : "rejecting");

            return success;
        }
        else
        {  // Server does validation through callback
            auto alpn = selected_alpn();

            log::debug(
                    log_cat,
                    "Quic {}: {} key verify callback{}",
                    local_name,
                    creds.key_verify ? "calling" : "did not provide",
                    creds.key_verify ? "" : "; accepting connection");

            // Key verify cb will return true on success, false on fail. Since this is only called if a client has
            // provided a certificate and is only called by the server, we can assume the following returns:
            //      true: the certificate was verified, and the connection is marked as validated
            //      false: the certificate was not verified, and the connection is rejected
            success = (creds.key_verify) ? creds.key_verify(_remote_key.view(), alpn) : true;

            return success;
        }
    }

}  // namespace oxen::quic
