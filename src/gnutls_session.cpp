#include "address.hpp"
#include "connection.hpp"
#include "crypto.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>

#include <cassert>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace oxen::quic
{
    struct IOContext;

    namespace
    {
        constexpr std::string_view translate_cert_type(gnutls_certificate_type_t type)
        {
            switch (static_cast<int>(type))
            {
                case 1:
                    return "<< X509 Cert >>"sv;
                case 2:
                    return "<< OpenPGP Cert >>"sv;
                case 3:
                    return "<< Raw PK Cert >>"sv;
                case 0:
                default:
                    return "<< Unknown Type >>"sv;
            }
        }

        std::string_view get_cert_type(gnutls_session_t session, gnutls_ctype_target_t type)
        {
            return translate_cert_type(gnutls_certificate_type_get2(session, type));
        }

    }  // namespace

    extern "C" int client_session_cb(
            gnutls_session_t session,
            unsigned int htype,
            unsigned /* when */,
            unsigned int /* incoming */,
            const gnutls_datum_t* /* msg */)
    {
        if (htype == GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
        {
            auto& conn = GNUTLSSession::conn_from(session);

            RemoteAddress remote{conn.remote_key(), conn.remote()};
            log::debug(log_cat, "received new tls session ticket from: {}", remote);

            gtls_datum data;
            if (auto rv = gnutls_session_get_data2(session, data); rv != 0)
            {
                log::warning(log_cat, "Failed to query session data: {}", gnutls_strerror(rv));
                return rv;
            }

            conn.get_creds()->store_session_ticket(conn, remote, std::span<const unsigned char>{data.data(), data.size()});
        }

        return 0;
    }

    GNUTLSSession& GNUTLSSession::from(gnutls_session_t g_session)
    {
        return from(conn_from(g_session));
    }

    GNUTLSSession& GNUTLSSession::from(Connection& conn)
    {
        auto* sess = conn.get_session();
        assert(dynamic_cast<GNUTLSSession*>(sess));
        return *static_cast<GNUTLSSession*>(sess);
    }

    Connection& GNUTLSSession::conn_from(gnutls_session_t g_session)
    {
        auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(g_session));
        assert(conn_ref);
        auto* conn = static_cast<Connection*>(conn_ref->user_data);
        assert(conn);
        return *conn;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    GNUTLSSession::GNUTLSSession(
            GNUTLSCreds& creds,
            const IOContext& /*ctx*/,
            Connection& c,
            std::span<const std::string> alpns,
            std::optional<gtls_key> expected_key) :
            creds{creds}, _is_client{c.is_outbound()}, _expected_remote_key{std::move(expected_key)}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        const auto direction_string = _is_client ? "Client"sv : "Server"sv;
        log::trace(log_cat, "Creating {} GNUTLSSession", direction_string);

        uint32_t init_flags = _is_client ? GNUTLS_CLIENT : GNUTLS_SERVER;

        // We send session tickets manually after QUIC handshake completes (if using 0rtt), as per
        // RFC 9001:
        init_flags |= GNUTLS_NO_AUTO_SEND_TICKET;

        const bool use_0rtt = _is_client ? creds.outbound_0rtt() : creds.inbound_0rtt();
        if (use_0rtt)
        {
            log::debug(log_cat, "Enabling early data for 0-RTT");
            init_flags |= GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA;
        }

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
            // NB: creds.priority_cache currently includes +CTYPE-CLI-ALL:+CTYPE-SRV-ALL which are
            // needed for raw_pk.  It isn't entirely clear if that is perfectly fine without raw_pk
            // mode, which is why this priority set call is inside this if(raw_pk) block.
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

            if (use_0rtt)
            {
                log::debug(log_cat, "Configuring gnutls for 0-RTT");
                if (creds.session_ticket_expiration > 0)
                    gnutls_db_set_cache_expiration(session, creds.session_ticket_expiration);

                gnutls_anti_replay_enable(session, creds.anti_replay);
                gnutls_record_set_max_early_data_size(session, 1048576);
                if (auto rv = gnutls_session_ticket_enable_server(session, creds.session_ticket_key); rv != 0)
                    log::error(
                            log_cat,
                            "gnutls_session_ticket_enable_server failed: {}; 0-RTT will not be available for this "
                            "connection",
                            gnutls_strerror(rv));
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

            if (use_0rtt)
            {
                log::trace(log_cat, "Setting client session ticket db hook...");
                gnutls_handshake_set_hook_function(
                        session, GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, GNUTLS_HOOK_POST, client_session_cb);
            }

            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }

            if (use_0rtt && _expected_remote_key)
            {
                RemoteAddress remote{*_expected_remote_key, c.remote()};
                if (auto maybe_session = creds.extract_session_data(remote))
                {
                    auto& [tls_ticket, quic_tp] = *maybe_session;
                    if (auto rv = gnutls_session_set_data(session, tls_ticket.data(), tls_ticket.size()); rv != 0)
                        log::warning(
                                log_cat,
                                "Invalid session ticket data ({}); 0-RTT disabled for connection",
                                gnutls_strerror(rv));
                    else
                    {
                        log::debug(log_cat, "TLS session ticket data loaded for 0-RTT");
                        // This TLSSession is created during Connection construction *before* we
                        // have an ngtcp2 conn, so we can't set this data yet: instead we stash it
                        // for Connection to deal with later in the Connection construction.
                        _0rtt_tp_data = std::move(quic_tp);
                    }
                }
                else
                {
                    log::debug(log_cat, "No session data found for {}, 0-RTT will not be used.", remote);
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

        std::string def_alpn;
        if (alpns.empty())
        {
            def_alpn = default_alpn_str;
            alpns = {&def_alpn, 1};
        }
        std::vector<gnutls_datum_t> allowed_alpns;
        for (auto& s : alpns)
        {
            log::trace(
                    log_cat,
                    "GNUTLS adding \"{}\" to {} ALPNs",
                    detail::to_span<char>(s.data(), s.size()),
                    direction_string);
            allowed_alpns.emplace_back(gnutls_datum_t{
                    reinterpret_cast<unsigned char*>(const_cast<char*>(s.data())), static_cast<unsigned int>(s.size())});
        }

        if (auto rv = gnutls_alpn_set_protocols(session, &allowed_alpns[0], allowed_alpns.size(), GNUTLS_ALPN_MANDATORY);
            rv < 0)
        {
            log::error(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_alpn_set_protocols failed");
        }
    }

    void GNUTLSSession::send_session_tickets()
    {
        log::trace(log_cat, "sending tls session tickets");
        if (auto rv = gnutls_session_ticket_send(session, 2, 0); rv != 0)
            log::error(log_cat, "gnutls_session_ticket_send failed: {}", gnutls_strerror(rv));
    }

    void GNUTLSSession::set_selected_alpn()
    {
        gnutls_datum_t _alpn{};

        if (auto rv = gnutls_alpn_get_selected_protocol(session, &_alpn); rv < 0)
        {
            auto err = "{} called, but ALPN negotiation incomplete."_format(__PRETTY_FUNCTION__);
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

        const auto local_name = _is_client ? "CLIENT"sv : "SERVER"sv;
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
            success = (creds.key_verify) ? creds.key_verify(_remote_key, selected_alpn()) : true;

            return success;
        }
    }

}  // namespace oxen::quic
