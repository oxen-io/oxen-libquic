#include "connection.hpp"
#include "endpoint.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"

namespace oxen::quic
{
    /*
        Client session resumption requires:
            gnutls_session_set_data to be called in TLSsession creation
            gnutls_session_get_data2 to be called in hook function after handshake completion
    */

    static constexpr auto SESSION_TICKET_HEADER = "GNUTLS SESSION PARAMETERS";

    int gtls_session_callbacks::server_anti_replay_cb(
            void* dbf, time_t exp_time, const gnutls_datum_t* key, const gnutls_datum_t* data)
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto* ep = static_cast<Endpoint*>(dbf);
        assert(ep);

        if (not ep->zero_rtt_enabled())
            throw std::runtime_error{"Anti-replay DB hook should not be called on 0rtt-disabled endpoint!"};

        return ep->validate_anti_replay(gtls_session_ticket::make(key, data), exp_time);
    }

    int gtls_session_callbacks::client_session_cb(
            gnutls_session_t session,
            unsigned int htype,
            unsigned /* when */,
            unsigned int /* incoming */,
            const gnutls_datum_t* /* msg */)
    {
        if (htype == GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
        {
            log::debug(log_cat, "Client received new session ticket from server!");
            auto* conn = get_connection_from_gnutls(session);
            auto remote_key = conn->remote_key();
            auto& ep = conn->endpoint();
            gtls_datum data{}, encoded{};

            if (auto rv = gnutls_session_get_data2(session, data); rv != 0)
            {
                log::warning(log_cat, "Failed to query session data: {}", gnutls_strerror(rv));
                return rv;
            }

            if (auto rv = gnutls_pem_base64_encode2(SESSION_TICKET_HEADER, data, encoded); rv != 0)
            {
                log::warning(log_cat, "Failed to encode session data: {}", gnutls_strerror(rv));
                return rv;
            }

            ep.store_session_ticket(gtls_session_ticket::make(remote_key, encoded));
        }

        return 0;
    }

    // Return value: 0 is pass, negative is fail
    int gtls_session_callbacks::cert_verify_callback_gnutls(gnutls_session_t session)
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto* conn = get_connection_from_gnutls(session);

        GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
        assert(tls_session);

        bool success = false;
        auto local_name = (conn->is_outbound()) ? "CLIENT" : "SERVER";

        //  true: Peer provided a valid cert; connection is accepted and marked validated
        //  false: Peer either provided an invalid cert or no cert; connection is rejected
        if (success = tls_session->validate_remote_key(); success)
            conn->set_validated();

        auto err = "Quic {} was {}able to validate peer certificate; {} connection!"_format(
                local_name, success ? "" : "un", success ? "accepting" : "rejecting");

        if (success)
            log::debug(log_cat, "{}", err);
        else
            log::error(log_cat, "{}", err);

        return !success;
    }

    Connection* get_connection_from_gnutls(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        return conn;
    }

    GNUTLSSession* get_session_from_gnutls(gnutls_session_t g_session)
    {
        auto* conn = get_connection_from_gnutls(g_session);
        GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
        assert(tls_session);
        return tls_session;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        if (not _is_client and _0rtt_enabled)
            gnutls_anti_replay_deinit(anti_replay);

        gnutls_deinit(session);
    }

    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            const std::shared_ptr<IOContext>& ctx,
            Connection& c,
            const std::vector<ustring>& alpns,
            std::optional<gtls_key> expected_key) :
            creds{creds}, _is_client{c.is_outbound()}, _0rtt_enabled{c.zero_rtt_enabled()}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        if (not _is_client and _0rtt_enabled)
        {
            gnutls_anti_replay_init(&anti_replay);
            gnutls_anti_replay_set_add_function(anti_replay, gtls_session_callbacks::server_anti_replay_cb);
            gnutls_anti_replay_set_ptr(anti_replay, &c.endpoint());
            gnutls_anti_replay_set_window(anti_replay, c.zero_rtt_window());

            if (auto rv = gnutls_session_ticket_key_generate(session_ticket_key); rv != 0)
            {
                auto err = "Server failed to generate session ticket key: {}"_format(gnutls_strerror(rv));
                log::error(log_cat, "{}", err);
                throw std::runtime_error{err};
            }
        }

        if (expected_key)
            _expected_remote_key = *expected_key;

        auto direction_string = (_is_client) ? "Client"s : "Server"s;
        log::trace(log_cat, "Creating {} GNUTLSSession with 0-rtt {}abled", direction_string, _0rtt_enabled ? "en" : "dis");

        uint32_t init_flags = _is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;

        if (_0rtt_enabled)
            init_flags |= GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA;
        else
            init_flags |= GNUTLS_NO_AUTO_SEND_TICKET;

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

        log::debug(
                log_cat,
                "[GNUTLS SESSION] Local ({}) cert type:{} \t Peer expecting cert type:{}",
                _is_client ? "CLIENT" : "SERVER",
                get_cert_type(session, GNUTLS_CTYPE_OURS),
                get_cert_type(session, GNUTLS_CTYPE_PEERS));

        if (not _is_client)
        {
            log::trace(log_cat, "gnutls configuring server session...");

            if (_0rtt_enabled)
            {
                if (auto rv = gnutls_session_ticket_enable_server(session, session_ticket_key); rv != 0)
                {
                    auto err = "gnutls_session_ticket_enable_server failed: {}"_format(gnutls_strerror(rv));
                    log::error(log_cat, "{}", err);
                    throw std::runtime_error{err};
                }

                gnutls_anti_replay_enable(session, anti_replay);
                gnutls_record_set_max_early_data_size(session, 0xffffffffu);
            }

            if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }

            // server always requests cert from client
            gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
        }
        else
        {
            log::trace(log_cat, "gnutls configuring client session...");

            if (_0rtt_enabled)
            {
                if (auto rv = gnutls_session_ticket_enable_client(session); rv != 0)
                {
                    auto err = "gnutls_session_ticket_enable_client failed: {}"_format(gnutls_strerror(rv));
                    log::error(log_cat, "{}", err);
                    throw std::runtime_error{err};
                }

                log::trace(log_cat, "Setting client session ticket db hook...");
                gnutls_handshake_set_hook_function(
                        session,
                        GNUTLS_HANDSHAKE_NEW_SESSION_TICKET,
                        GNUTLS_HOOK_POST,
                        gtls_session_callbacks::client_session_cb);
            }

            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }

            if (_0rtt_enabled and _expected_remote_key)
            {
                if (auto maybe_ticket = c.endpoint().get_session_ticket(_expected_remote_key.view()))
                {
                    gtls_datum d{};

                    if (auto rv = gnutls_pem_base64_decode2(SESSION_TICKET_HEADER, maybe_ticket->datum(), d); rv != 0)
                    {
                        log::warning(log_cat, "Failed to decode session ticket: {}", ngtcp2_strerror(rv));
                        throw std::runtime_error("gnutls_pem_base64_decode2 failed");
                    }

                    if (auto rv = gnutls_session_set_data(session, d.data(), d.size()); rv != 0)
                    {
                        log::warning(log_cat, "Failed to set decoded session data: {}", ngtcp2_strerror(rv));
                        throw std::runtime_error("gnutls_session_set_data failed");
                    }
                }
            }
        }

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds.cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_credentials_set failed");
        }

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (_is_client)
        {
            if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            {
                log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_server_name_set failed");
            }
        }

        if (alpns.size())
        {
            std::vector<gnutls_datum_t> allowed_alpns;
            for (auto& s : alpns)
            {
                log::trace(
                        log_cat,
                        "GNUTLS adding \"{}\" to {} ALPNs",
                        to_sv(ustring_view{s.data(), s.size()}),
                        direction_string);
                allowed_alpns.emplace_back(
                        gnutls_datum_t{const_cast<unsigned char*>(s.data()), static_cast<unsigned int>(s.size())});
            }

            if (auto rv = gnutls_alpn_set_protocols(session, &allowed_alpns[0], allowed_alpns.size(), GNUTLS_ALPN_MANDATORY);
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

        if (not ctx->disable_key_verification)
        {
            log::debug(log_cat, "Setting key verify hook for {}bound session...", _is_client ? "out" : "in");
            gnutls_session_set_verify_function(session, gtls_session_callbacks::cert_verify_callback_gnutls);
        }
        else
            log::info(log_cat, "Key verification has been turned OFF for this session!");
    }

    int GNUTLSSession::send_session_ticket()
    {
        auto rv = gnutls_session_ticket_send(session, 1, 0);

        if (rv != 0)
        {
            log::error(log_cat, "gnutls_session_ticket_send failed: {}", gnutls_strerror(rv));
            return -1;
        }

        return 0;
    }

    void GNUTLSSession::set_selected_alpn()
    {
        gnutls_datum_t _alpn{};

        if (auto rv = gnutls_alpn_get_selected_protocol(session, &_alpn); rv < 0)
        {
            auto err = fmt::format("{} called, but ALPN negotiation incomplete.", __PRETTY_FUNCTION__);
            log::error(log_cat, "{}", err);
            throw std::logic_error(err);
        }

        _selected_alpn.resize(_alpn.size);
        std::memmove(_selected_alpn.data(), _alpn.data, _alpn.size);
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

        const auto local_name = _is_client ? "CLIENT" : "SERVER";
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

        log::trace(
                log_cat,
                "Quic {} validating pubkey \"cert\" of len {}B:\n{}\n",
                local_name,
                cert_size,
                buffer_printer{cert_data, cert_size});

        // pubkey comes as 12 bytes header + 32 bytes key
        _remote_key.write(cert_data, cert_size);

        set_selected_alpn();

        if (_is_client)
        {
            // Client does validation through a remote pubkey provided when calling endpoint::connect
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
        {
            // Server does validation through callback
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
            success = (creds.key_verify) ? creds.key_verify(_remote_key.view(), selected_alpn()) : true;

            return success;
        }
    }

}  // namespace oxen::quic
