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
            assert(tls_session->get_session() == session);

            return tls_session->do_tls_callback(session, htype, when, incoming, msg);
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

    GNUTLSSession::~GNUTLSSession()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    void GNUTLSSession::set_tls_hook_functions()
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, gnutls_callback_wrapper);
    }

    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            bool is_client,
            const std::vector<std::string>& alpns,
            std::optional<gnutls_key> expected_key) :
            creds{creds}, is_client{is_client}, expected_remote_key{expected_key}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        auto direction_string = (is_client) ? "Client"s : "Server"s;
        log::trace(log_cat, "Creating {} GNUTLSSession", direction_string);

        uint32_t init_flags = is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;
        if (creds.using_raw_pk)
        {
            log::trace(log_cat, "Setting GNUTLS_ENABLE_RAWPK flag on gnutls_init");
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
            if (auto rv = gnutls_alpn_set_protocols(session, &gnutls_default_alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            {
                log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_alpn_set_protocols failed");
            }
        }

        if (creds.using_raw_pk)
        {
            // server always requests cert from client in raw public key mode
            if (not is_client)
            {
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
            }
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

    std::string_view GNUTLSSession::selected_alpn()
    {
        gnutls_datum_t proto;
        if (auto rv = gnutls_alpn_get_selected_protocol(session, &proto); rv < 0)
        {
            auto err = fmt::format("{} called, but ALPN negotiation incomplete.", __PRETTY_FUNCTION__);
            throw std::logic_error(err);
        }

        return proto.size ? std::string_view{(const char*)proto.data, proto.size} : ""sv;
    }

    int GNUTLSSession::do_tls_callback(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& policy = (is_client) ? creds.client_tls_policy : creds.server_tls_policy;

        if (policy)
        {
            if (policy.htype == htype && policy.when == when && policy.incoming == incoming)
            {
                log::debug(log_cat, "Calling {} tls policy cb", (is_client) ? "client" : "server");
                return policy(session, htype, when, incoming, msg);
            }
        }
        return 0;
    }

    bool GNUTLSSession::validate_remote_key()
    {
        log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);

        gnutls_certificate_type_t cert_type;

        cert_type = gnutls_certificate_type_get2(session, GNUTLS_CTYPE_PEERS);
        uint32_t cert_list_size = 0;
        const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
        if (cert_list_size == 0)
        {
            log::error(log_cat, "{} called, but peers cert list is empty.", __PRETTY_FUNCTION__);
            return false;
        }

        // this function is only for raw pubkey mode, and should not be called otherwise
        if (cert_type != GNUTLS_CRT_RAWPK)
        {
            log::error(log_cat, "{} called, but remote cert type is not raw pubkey.", __PRETTY_FUNCTION__);
            return false;
        }

        if (cert_list_size != 1)
        {
            log::error(log_cat, "{} called, but peers cert list has more than one entry.", __PRETTY_FUNCTION__);
            return false;
        }

        auto* cert_data = cert_list[0].data;
        auto cert_size = cert_list[0].size;
        log::warning(
                log_cat,
                "Validating pubkey \"cert\" of len {}:\n\n{}\n\n",
                cert_size,
                oxenc::to_hex(cert_data, cert_data + cert_size));

        // pubkey comes as 12 bytes header + 32 bytes key
        std::copy(cert_data + 12, cert_data + 44, remote_key.data());

        auto alpn = selected_alpn();

        if (is_client and expected_remote_key)
        {
            if (remote_key != *expected_remote_key)
            {
                log::error(log_cat, "Outbound connection received wrong public key from other end!");
                return false;
            }
            log::trace(log_cat, "Outbound connection received expected public key from other end.");
        }
        else if ((not is_client) and creds.key_verify)
        {
            log::trace(log_cat, "{}: Calling key verify callback", __PRETTY_FUNCTION__);
            return creds.key_verify(remote_key, alpn);
        }

        log::trace(log_cat, "{} reached end, defaulting to return true", __PRETTY_FUNCTION__);

        return true;
    }

}  // namespace oxen::quic
