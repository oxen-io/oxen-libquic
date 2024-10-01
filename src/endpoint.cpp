#include "endpoint.hpp"

#include "opt.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>
#ifdef __linux__
#include <netinet/udp.h>
#endif
}

#include <cstddef>
#include <list>
#include <optional>

#include "connection.hpp"
#include "gnutls_crypto.hpp"
#include "internal.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    void Endpoint::handle_ep_opt(opt::enable_datagrams dc)
    {
        _datagrams = true;
        _packet_splitting = dc.split_packets;
        _policy = dc.mode;
        _rbufsize = dc.bufsize;

        log::trace(
                log_cat,
                "User has activated endpoint datagram support with {} split-packet support",
                _packet_splitting ? "" : "no");
    }

    void Endpoint::handle_ep_opt(opt::outbound_alpns alpns)
    {
        outbound_alpns = std::move(alpns.alpns);
    }

    void Endpoint::handle_ep_opt(opt::inbound_alpns alpns)
    {
        inbound_alpns = std::move(alpns.alpns);
    }

    void Endpoint::handle_ep_opt(opt::alpns alpns)
    {
        inbound_alpns = std::move(alpns.inout_alpns);
        outbound_alpns = inbound_alpns;
    }

    void Endpoint::handle_ep_opt(opt::handshake_timeout timeout)
    {
        handshake_timeout = timeout.timeout;
    }

    void Endpoint::handle_ep_opt(dgram_data_callback func)
    {
        log::trace(log_cat, "Endpoint given datagram recv callback");
        dgram_recv_cb = std::move(func);
    }

    void Endpoint::handle_ep_opt(connection_established_callback conn_established_cb)
    {
        log::trace(log_cat, "Endpoint given connection established callback");
        connection_established_cb = std::move(conn_established_cb);
    }

    void Endpoint::handle_ep_opt(connection_closed_callback conn_closed_cb)
    {
        log::trace(log_cat, "Endpoint given connection closed callback");
        connection_close_cb = std::move(conn_closed_cb);
    }

    void Endpoint::handle_ep_opt(opt::static_secret secret)
    {
        _static_secret = std::move(secret.secret);
        assert(_static_secret.size() >= 16);  // opt::static_secret should have checked this
    }

    void Endpoint::handle_ep_opt(opt::manual_routing mrouting)
    {
        _manual_routing = std::move(mrouting);
    }

    void Endpoint::handle_ep_opt(opt::enable_0rtt_ticketing rtt)
    {
        _0rtt_enabled = true;
        _0rtt_window = rtt.window.count();

        _validate_0rtt_ticket = rtt._check ? std::move(rtt._check) : [this](gtls_ticket_ptr ticket, time_t current) -> bool {
            auto key = ticket->key();

            if (auto it = session_tickets.find(key); it != session_tickets.end())
            {
                if (auto exp = gnutls_db_check_entry_expire_time(*it->second); current < exp)
                {
                    log::info(log_cat, "Found existing anti-replay ticket for incoming connection; rejecting...");
                    return GNUTLS_E_DB_ENTRY_EXISTS;
                }

                log::debug(log_cat, "Found expired anti-replay ticket for incoming connection");
            }

            session_tickets[std::move(key)] = std::move(ticket);
            return 0;
        };

        _get_session_ticket = rtt._fetch ? std::move(rtt._fetch) : [this](ustring_view key) -> gtls_ticket_ptr {
            gtls_ticket_ptr ret = nullptr;
            if (auto it = session_tickets.find(key); it != session_tickets.end())
            {
                ret = std::move(it->second);
                session_tickets.erase(it);
                log::debug(log_cat, "Found session ticket for remote; entry extracted and returned...");
            }
            else
                log::debug(log_cat, "Could not find session ticket for remote!");

            return ret;
        };

        _put_session_ticket = rtt._put ? std::move(rtt._put) : [this](gtls_ticket_ptr ticket, time_t /* exp */) {
            auto key = ticket->key();
            auto [_, b] = session_tickets.insert_or_assign(std::move(key), std::move(ticket));

            log::debug(
                    log_cat, "Stored anti-replay ticket for connection to remote{}!", b ? "" : "; old ticket overwritten");
        };
    }

    void Endpoint::handle_ep_opt(opt::disable_stateless_reset /* rst */)
    {
        _stateless_reset_enabled = false;
    }

    ConnectionID Endpoint::next_reference_id()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(in_event_loop());
        return ConnectionID{++_next_rid};
    }

    ustring Endpoint::make_static_secret()
    {
        ustring secret;
        secret.resize(32);
        gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, secret.data(), secret.size());
        return secret;
    }

    void Endpoint::manually_receive_packet(Packet&& pkt)
    {
        call([this, packet = std::move(pkt)]() mutable { handle_packet(std::move(packet)); });
    }

    void Endpoint::_init_internals()
    {
        if (not _manual_routing)
        {
            log::debug(log_cat, "Starting new UDP socket on {}", _local);
            socket = std::make_unique<UDPSocket>(
                    get_loop().get(), _local, [this](auto&& packet) { handle_packet(std::move(packet)); });

            _local = socket->address();
        }
        else
            log::info(log_cat, "Endpoint enabled with manual packet routing -- bypassing UDP socket creation!");

        expiry_timer.reset(event_new(
                get_loop().get(),
                -1,          // Not attached to an actual socket
                EV_PERSIST,  // Stays active (i.e. repeats) once fired
                [](evutil_socket_t, short, void* self) { static_cast<Endpoint*>(self)->check_timeouts(); },
                this));
        timeval exp_interval;
        exp_interval.tv_sec = 0;
        exp_interval.tv_usec = 250'000;
        event_add(expiry_timer.get(), &exp_interval);
    }

    void Endpoint::_listen()
    {
        _set_context_globals(inbound_ctx);
        _accepting_inbound = true;

        log::debug(log_cat, "Inbound context ready for incoming connections");
    }

    void Endpoint::_connect(
            RemoteAddress remote, quic_cid qcid, ConnectionID rid, std::promise<std::shared_ptr<Connection>>& p)
    {
        Path path = Path{_local, remote};
        auto remote_pk = std::move(remote).get_remote_key();

        for (;;)
        {
            // emplace random CID into lookup keyed to unique reference ID
            if (auto [it_a, res_a] = conn_lookup.emplace(quic_cid::random(), rid); res_a)
            {
                qcid = it_a->first;

                if (auto [it_b, res_b] = conns.emplace(rid, nullptr); res_b)
                {
                    it_b->second = Connection::make_conn(
                            *this,
                            rid,
                            it_a->first,
                            quic_cid::random(),
                            std::move(path),
                            outbound_ctx,
                            outbound_alpns,
                            handshake_timeout,
                            remote_pk);

                    p.set_value(it_b->second);
                    return;
                }
            }
        }
    }

    void Endpoint::_connect(Address remote, quic_cid qcid, ConnectionID rid, std::promise<std::shared_ptr<Connection>>& p)
    {
        Path path = Path{_local, std::move(remote)};

        for (;;)
        {
            // emplace random CID into lookup keyed to unique reference ID
            if (auto [it_a, res_a] = conn_lookup.emplace(quic_cid::random(), rid); res_a)
            {
                qcid = it_a->first;

                if (auto [it_b, res_b] = conns.emplace(rid, nullptr); res_b)
                {
                    it_b->second = Connection::make_conn(
                            *this,
                            rid,
                            it_a->first,
                            quic_cid::random(),
                            std::move(path),
                            outbound_ctx,
                            outbound_alpns,
                            handshake_timeout);

                    p.set_value(it_b->second);
                    return;
                }
            }
        }
    }

    void Endpoint::_set_context_globals(std::shared_ptr<IOContext>& ctx)
    {
        ctx->config.datagram_support = _datagrams;
        ctx->config.split_packet = _packet_splitting;
        ctx->config.policy = _policy;
    }

    std::list<std::shared_ptr<connection_interface>> Endpoint::get_all_conns(std::optional<Direction> d)
    {
        std::list<std::shared_ptr<connection_interface>> ret{};

        for (const auto& c : conns)
        {
            if (d)
            {
                if (c.second->direction() == d)
                    ret.emplace_back(c.second);
            }
            else
                ret.emplace_back(c.second);
        }

        return ret;
    }

    void Endpoint::close_conns(std::optional<Direction> d)
    {
        // We need to defer this because we aren't allowed to close connections during some other
        // callback, and can't guarantee we aren't in such a callback.
        call_soon([this, d] { _close_conns(d); });
    }

    void Endpoint::_close_conns(std::optional<Direction> d)
    {
        // We have to do this in two passes rather than just closing as we go because
        // `_close_connection` can remove from `conns`, invalidating our implicit iterator.
        std::vector<Connection*> close_me;

        for (const auto& c : conns)
            if (c.second && (!d || *d == c.second->direction()))
                close_me.push_back(c.second.get());
        for (auto* c : close_me)
            _close_connection(*c, io_error{0}, "NO_ERROR");
    }

    void Endpoint::drain_connection(Connection& conn)
    {
        if (conn.is_draining() || conn.is_closing())
            return;

        conn.halt_events();
        conn.set_draining();

        const auto* err = ngtcp2_conn_get_ccerr(conn);

        log::debug(
                log_cat,
                "Dropping connection ({}), Reason: {}",
                conn.reference_id(),
                err->reason ? std::string_view{reinterpret_cast<const char*>(err->reason), err->reasonlen} : "None"sv);

        _execute_close_hooks(conn, io_error{err->error_code});

        draining_closing.emplace(get_time() + ngtcp2_conn_get_pto(conn) * 3 * 1ns, conn.reference_id());

        log::debug(log_cat, "Connection ({}) marked as draining", conn.reference_id());
    }

    void Endpoint::handle_packet(Packet&& pkt)
    {
        auto dcid_opt = handle_packet_connid(pkt);

        if (!dcid_opt)
        {
            log::warning(log_cat, "Error: initial packet handling failed");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        log::trace(log_cat, "Incoming connection ID: {}", dcid);

        auto cptr = fetch_associated_conn(dcid);

        if (!cptr)
        {
            if (_accepting_inbound)
            {
                cptr = accept_initial_connection(pkt, dcid);

                if (!cptr)
                {
                    if (_stateless_reset_enabled)  // must be done within the check for _accepting_inbound
                    {
                        send_stateless_reset(pkt, dcid);
                        log::debug(
                                log_cat,
                                "Server failed to decode pkt: dispatched reset token to remote ({})",
                                pkt.path.remote);
                    }
                    else
                        log::warning(log_cat, "Error: connection could not be created");
                    return;
                }

                initial_association(*cptr);
            }
            else
            {
                log::info(log_cat, "Dropping packet; unknown connection ID to endpoint not accepting inbound conns");
                return;
            }
        }
        else
            log::debug(log_cat, "Found associated connection to incoming DCID!");

        if (cptr->is_outbound())
            // For a inbound packet on an outbound connection the packet handling code will have set
            // the actual ip address in the packet, but that might not match the path that we
            // created the connection with (because, often, we create using the any address), so
            // forcibly reset the local address to the endpoint bind address so that we don't see it
            // on an unknown path because of the anyaddr != specific address mismatch.
            //
            // We *don't* want to do this for inbound connections because we absolutely have to
            // return those from the same address they arrived on (otherwise, on a multi-IP machine,
            // you could have something arrive on IP2 but reply on IP1, which the remote side will
            // not accept).
            pkt.path.local = _local;

        cptr->handle_conn_packet(std::move(pkt));
    }

    void Endpoint::drop_connection(Connection& conn, io_error err)
    {
        log::debug(log_cat, "Dropping connection ({}) with errcode {}", conn.reference_id(), err.code());

        _execute_close_hooks(conn, std::move(err));

        delete_connection(conn);
    }

    void Endpoint::close_connection(Connection& conn, io_error ec, std::optional<std::string> msg)
    {
        if (!msg)
            msg = ec.strerror();
        call_soon([this, connid = conn.reference_id(), ec = std::move(ec), msg = std::move(*msg)]() mutable {
            if (auto it = conns.find(connid); it != conns.end() && it->second)
                _close_connection(*it->second, std::move(ec), std::move(msg));
        });
    }

    void Endpoint::_execute_close_hooks(Connection& conn, io_error ec)
    {
        if (not conn.closing_quietly())
        {
            conn.close_all_streams();

            // prioritize connection level callback over endpoint level
            if (conn.conn_closed_cb)
            {
                log::trace(log_cat, "{} Calling Connection-level close callback", conn.is_inbound() ? "server" : "client");
                conn.conn_closed_cb(conn, ec.code());
            }
            else if (connection_close_cb)
            {
                log::trace(log_cat, "{} Calling Endpoint-level close callback", conn.is_inbound() ? "server" : "client");
                connection_close_cb(conn, ec.code());
            }
        }
    }

    void Endpoint::_close_connection(Connection& conn, io_error ec, std::string msg)
    {
        log::debug(log_cat, "Closing connection ({})", conn.reference_id());

        assert(in_event_loop());

        if (conn.is_closing() || conn.is_draining())
            return;

        // mark connection as closing so that if we re-enter we won't try closing a second time
        conn.set_closing();
        conn.halt_events();

        if (ec.ngtcp2_code() == NGTCP2_ERR_IDLE_CLOSE)
        {
            log::info(
                    log_cat,
                    "Connection ({}) passed idle expiry timer; closing now without close packet",
                    conn.reference_id());
            drop_connection(conn, io_error{CONN_IDLE_CLOSED});
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (ec.ngtcp2_code() == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            log::info(
                    log_cat,
                    "Connection ({}) timed out during handshake; closing now with close packet",
                    conn.reference_id());
        }

        _execute_close_hooks(conn, ec);

        ngtcp2_ccerr err;
        ngtcp2_ccerr_default(&err);
        if (ec.is_ngtcp2)
            ngtcp2_ccerr_set_liberr(&err, ec.ngtcp2_code(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        else
            ngtcp2_ccerr_set_application_error(&err, ec.code(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);
        ngtcp2_pkt_info pkt_info{};

        auto written = ngtcp2_conn_write_connection_close(
                conn, nullptr, &pkt_info, u8data(buf), buf.size(), &err, get_timestamp().count());

        if (written <= 0)
        {
            log::warning(
                    log_cat,
                    "Error: Failed to write connection close packet: {}",
                    (written < 0) ? ngtcp2_strerror(written) : "[Error Unknown: closing pkt is 0 bytes?]"s);

            delete_connection(conn);
            return;
        }
        // ensure we had enough write space
        assert(static_cast<size_t>(written) <= buf.size());
        buf.resize(written);

        log::debug(log_cat, "Marked connection ({}) as closing; sending close packet", conn.reference_id());

        draining_closing.emplace(get_time() + ngtcp2_conn_get_pto(conn) * 3 * 1ns, conn.reference_id());

        send_or_queue_packet(conn.path_impl(), std::move(buf), /*ecn=*/0, [this, &conn](io_result rv) {
            if (rv.failure())
            {
                log::warning(
                        log_cat,
                        "Error: failed to send close packet [{}]; removing connection ({})",
                        rv.str_error(),
                        conn.reference_id());
                delete_connection(conn);
            }
        });
    }

    void Endpoint::delete_connection(Connection& conn)
    {
        const auto& rid = conn.reference_id();

        conn.halt_events();

        log::debug(log_cat, "Deleting associated CIDs for connection {}", rid);

        if (conn.is_inbound())
        {
            dissociate_cid(ngtcp2_conn_get_client_initial_dcid(conn), conn);
        }

        auto& cids = conn.associated_cids();

        log::debug(log_cat, "Deleting {} associated CIDs for connection {}", cids.size(), rid);

        while (not cids.empty())
        {
            auto itr = cids.begin();
            // call to dissociate_cid deletes from cids in Connection object
            if (_stateless_reset_enabled)
                deactivate_cid(&*itr, conn);
            else
                dissociate_cid(*itr, conn);
        }

        conn.drop_streams();

        if (auto it = conns.find(rid); it != conns.end())
        {
            // Defer destruction until the next event loop tick because there are code paths that
            // can land here from within an ongoing connection method and so it isn't safe to allow
            // the Connection to get destroyed right now.
            reset_soon(std::move(it->second));
            // We do want to remove it from `conns`, though, because some scheduled callbacks check
            // for `rid` being still in the endpoint and so, in that respect, we want the connection
            // to be considered gone even if its destructor doesn't fire yet.
            conns.erase(it);
            log::debug(log_cat, "Deleted connection ({})", rid);
        }
    }

    int Endpoint::validate_anti_replay(gtls_session_ticket ticket, time_t current)
    {
        return _validate_0rtt_ticket(gtls_session_ticket::make(std::move(ticket)), current) ? 0 : GNUTLS_E_DB_ENTRY_EXISTS;
    }

    void Endpoint::store_session_ticket(gtls_session_ticket ticket)
    {
        log::trace(log_cat, "Storing session ticket...");
        return _put_session_ticket(gtls_session_ticket::make(std::move(ticket)), 0);
    }

    gtls_ticket_ptr Endpoint::get_session_ticket(const ustring_view& remote_pk)
    {
        log::trace(log_cat, "Fetching session ticket (remote key: {})...", buffer_printer{remote_pk});
        return _get_session_ticket(remote_pk);
    }

    void Endpoint::store_0rtt_transport_params(Address remote, ustring encoded_params)
    {
        log::trace(log_cat, "Storing 0rtt tranpsport params...");
        encoded_transport_params.insert_or_assign(std::move(remote), std::move(encoded_params));
    }

    std::optional<ustring> Endpoint::get_0rtt_transport_params(const Address& remote)
    {
        log::trace(log_cat, "Fetching 0rtt transport params...");
        if (auto itr = encoded_transport_params.find(remote); itr != encoded_transport_params.end())
            return itr->second;

        return std::nullopt;
    }

    void Endpoint::initial_association(Connection& conn)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(in_event_loop());

        std::array<ngtcp2_cid, MAX_ACTIVE_CIDS> scids;

        auto dir_str = conn.is_outbound() ? "CLIENT"s : "SERVER"s;
        auto n = ngtcp2_conn_get_scid(conn, nullptr);

        log::trace(log_cat, "{} associating {} active initial CID's", dir_str, n);

        ngtcp2_conn_get_scid(conn, scids.data());

        for (size_t i = 0; i < n; ++i)
            associate_cid(&scids[0], conn);

        log::debug(log_cat, "Connection (RID:{}) completed initial CID association", conn.reference_id());
    }

    void Endpoint::activate_cid(const ngtcp2_cid* cid, const uint8_t* token, Connection& conn)
    {
        assert(in_event_loop());
        auto qcid = quic_cid{*cid};
        log::debug(
                log_cat,
                "{} activating new CID:{} with reset token for {}",
                conn.is_inbound() ? "SERVER" : "CLIENT",
                qcid,
                conn.reference_id());
        associate_cid(qcid, conn);

        // We only hold one reset token per connection at a time!
        auto [it, _] = reset_token_map.emplace(gtls_reset_token::make_copy(token), qcid);
        reset_token_lookup[qcid] = it->first;
    }

    void Endpoint::deactivate_cid(const ngtcp2_cid* cid, Connection& conn)
    {
        assert(in_event_loop());
        auto qcid = quic_cid{*cid};
        log::debug(
                log_cat,
                "{} deactivating CID:{} with reset token for {}",
                conn.is_inbound() ? "SERVER" : "CLIENT",
                qcid,
                conn.reference_id());
        dissociate_cid(qcid, conn);

        if (auto it = reset_token_lookup.find(qcid); it != reset_token_lookup.end())
        {
            reset_token_map.erase(it->second);
            reset_token_lookup.erase(it);
            log::debug(log_cat, "Successfully deleted token for deactivated CID:{}", qcid);
        }
        else
            log::debug(log_cat, "Could not find token corresponding to deactivated CID:{}", qcid);
    }

    void Endpoint::associate_cid(quic_cid qcid, Connection& conn)
    {
        assert(in_event_loop());
        log::trace(
                log_cat, "{} associating CID:{} to {}", conn.is_inbound() ? "SERVER" : "CLIENT", qcid, conn.reference_id());

        conn_lookup.emplace(qcid, conn.reference_id());
        conn.store_associated_cid(qcid);
    }

    void Endpoint::associate_cid(const ngtcp2_cid* cid, Connection& conn)
    {
        assert(in_event_loop());
        if (cid->datalen)
            return associate_cid(quic_cid{*cid}, conn);
    }

    void Endpoint::dissociate_cid(quic_cid qcid, Connection& conn)
    {
        assert(in_event_loop());
        log::trace(
                log_cat, "{} dissociating CID:{} to {}", conn.is_inbound() ? "SERVER" : "CLIENT", qcid, conn.reference_id());

        conn_lookup.erase(qcid);
        conn.delete_associated_cid(qcid);
    }

    void Endpoint::dissociate_cid(const ngtcp2_cid* cid, Connection& conn)
    {
        assert(in_event_loop());
        if (cid->datalen)
            return dissociate_cid(quic_cid{*cid}, conn);
    }

    Connection* Endpoint::fetch_associated_conn(quic_cid& ccid)
    {
        if (auto it_a = conn_lookup.find(ccid); it_a != conn_lookup.end())
        {
            if (auto it_b = conns.find(it_a->second); it_b != conns.end())
            {
                return it_b->second.get();
            }
        }

        log::debug(log_cat, "Could not find connection associated with {}", ccid);

        return nullptr;
    }

    bool Endpoint::verify_token(const Packet& pkt, ngtcp2_pkt_hd* hdr)
    {
        auto now = get_timestamp().count();

        if (auto rv = ngtcp2_crypto_verify_regular_token(
                    hdr->token,
                    hdr->tokenlen,
                    _static_secret.data(),
                    _static_secret.size(),
                    pkt.path.remote,
                    pkt.path.remote.socklen(),
                    3600 * NGTCP2_SECONDS,
                    now);
            rv != 0)
        {
            log::critical(
                    log_cat,
                    "Server (local={}) could not verify regular token! path: [local={}, remote={}]",
                    _local,
                    pkt.path.local,
                    pkt.path.remote);
            return false;
        }

        log::critical(log_cat, "Server successfully verified regular token!");
        return true;
    }

    bool Endpoint::verify_retry_token(const Packet& pkt, ngtcp2_pkt_hd* hdr, ngtcp2_cid* ocid)
    {
        auto now = get_timestamp().count();

        if (auto rv = ngtcp2_crypto_verify_retry_token(
                    ocid,
                    hdr->token,
                    hdr->tokenlen,
                    _static_secret.data(),
                    _static_secret.size(),
                    hdr->version,
                    pkt.path.remote,
                    pkt.path.remote.socklen(),
                    &hdr->dcid,
                    10 * NGTCP2_SECONDS,
                    now);
            rv != 0)
        {
            log::warning(log_cat, "Server could not verify retry token!");
            return false;
        }

        log::debug(log_cat, "Server successfully verified retry token!");
        return true;
    }

    void Endpoint::send_stateless_reset(const Packet& pkt, quic_cid& cid)
    {
        auto token = gtls_reset_token::generate(_static_secret.data(), _static_secret.size(), cid);

        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);

        auto nwrite =
                ngtcp2_pkt_write_stateless_reset(u8data(buf), buf.size(), token->token(), token->rand(), token->RANDSIZE);

        if (nwrite < 0)
        {
            log::warning(log_cat, "Server failed to write stateless reset packet!");
            return;
        }

        // ensure we had enough write space
        assert(static_cast<size_t>(nwrite) <= buf.size());
        buf.resize(nwrite);

        send_or_queue_packet(pkt.path, std::move(buf), /* ecn */ 0);
    }

    void Endpoint::send_retry(const Packet& pkt, ngtcp2_pkt_hd* hdr)
    {
        ngtcp2_cid scid;
        scid.datalen = NGTCP2_RETRY_SCIDLEN;

        if (auto rv = gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen); rv != 0)
        {
            log::warning(log_cat, "Server failed to generate retry SCID!");
            return;
        }

        auto now = get_timestamp().count();
        std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN> token;

        auto len = ngtcp2_crypto_generate_retry_token(
                token.data(),
                _static_secret.data(),
                _static_secret.size(),
                hdr->version,
                pkt.path.remote,
                pkt.path.remote.socklen(),
                &scid,
                &hdr->dcid,
                now);

        if (len < 0)
        {
            log::warning(log_cat, "Server failed to generate retry token!");
            return;
        }

        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);

        auto nwrite = ngtcp2_crypto_write_retry(
                u8data(buf), buf.size(), hdr->version, &hdr->scid, &scid, &hdr->dcid, token.data(), len);

        if (nwrite < 0)
        {
            log::warning(log_cat, "Server failed to write retry packet!");
            return;
        }

        // ensure we had enough write space
        assert(static_cast<size_t>(nwrite) <= buf.size());
        buf.resize(nwrite);

        send_or_queue_packet(pkt.path, std::move(buf), /* ecn */ 0);
    }

    void Endpoint::send_stateless_connection_close(const Packet& pkt, ngtcp2_pkt_hd* hdr, io_error ec)
    {
        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);

        auto nwrite = ngtcp2_crypto_write_connection_close(
                u8data(buf), buf.size(), hdr->version, &hdr->scid, &hdr->dcid, ec.code(), nullptr, 0);

        if (nwrite < 0)
        {
            log::warning(log_cat, "Error: failed to write stateless connection close!");
            return;
        }

        assert(static_cast<size_t>(nwrite) <= buf.size());
        buf.resize(nwrite);

        send_or_queue_packet(pkt.path, std::move(buf), /* ecn */ 0);
    }

    void Endpoint::store_path_validation_token(Address remote, ustring token)
    {
        path_validation_tokens.insert_or_assign(std::move(remote), std::move(token));
    }

    std::optional<ustring> Endpoint::get_path_validation_token(const Address& remote)
    {
        if (auto itr = path_validation_tokens.find(remote); itr != path_validation_tokens.end())
            return itr->second;

        return std::nullopt;
    }

    void Endpoint::connection_established(connection_interface& conn)
    {
        log::trace(log_cat, "Connection established, calling user callback ({})", conn.reference_id());

        if (connection_established_cb)
            connection_established_cb(conn);
    }

    std::optional<quic_cid> Endpoint::handle_packet_connid(const Packet& pkt)
    {
        ngtcp2_version_cid vid;
        auto data = pkt.data<uint8_t>();
        auto rv = ngtcp2_pkt_decode_version_cid(&vid, data.data(), data.size(), NGTCP2_MAX_CIDLEN);

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {  // version negotiation has not been sent yet, ignore packet
            send_version_negotiation(vid, pkt.path);
            return std::nullopt;
        }
        if (rv != 0)
        {
            log::debug(log_cat, "Error: failed to decode QUIC packet header [code: {}]", ngtcp2_strerror(rv));
            return std::nullopt;
        }

        if (vid.dcidlen > NGTCP2_MAX_CIDLEN)
        {
            log::debug(
                    log_cat,
                    "Error: destination ID is longer than NGTCP2_MAX_CIDLEN ({} > {})",
                    vid.dcidlen,
                    NGTCP2_MAX_CIDLEN);
            return std::nullopt;
        }

        return std::make_optional<quic_cid>(vid.dcid, vid.dcidlen);
    }

    Connection* Endpoint::check_stateless_reset(const Packet& pkt, quic_cid& /* cid */)
    {
        log::trace(log_cat, "Checking last 16B of pkt for stateless reset token...");
        Connection* cptr = nullptr;

        auto gtls_token = gtls_reset_token::parse_packet(pkt);

        if (auto rit = reset_token_map.find(gtls_token); rit != reset_token_map.end())
        {
            if (cptr = get_conn(rit->second); cptr)
            {
                log::info(log_cat, "Matched stateless reset token in unknown packet to connection {}", cptr->reference_id());
                reset_token_lookup.erase(rit->second);
            }
            else
                log::warning(log_cat, "Received good stateless reset token but no connection exists for it; deleting entry");

            reset_token_map.erase(rit);
        }
        else
            log::trace(log_cat, "No stateless reset token match for pkt from remote: {}", pkt.path.remote);

        return cptr;
    }

    Connection* Endpoint::accept_initial_connection(const Packet& pkt, quic_cid& dcid)
    {
        log::trace(log_cat, "Accepting new connection...");

        ngtcp2_pkt_hd hdr;

        auto data = pkt.data<uint8_t>();
        auto rv = ngtcp2_accept(&hdr, data.data(), data.size());

        if (rv < 0)  // catches all other possible ngtcp2 errors
        {
            if (_stateless_reset_enabled)
            {
                // TODO: may not need this if the ngtcp2 cb works as it should...?
                return check_stateless_reset(pkt, dcid);
            }
            else
                log::warning(
                        log_cat,
                        "Unknown packet received from {}, length={}, code={}; ignoring it.",
                        pkt.path.remote,
                        data.size(),
                        ngtcp2_strerror(rv));
            return nullptr;
        }

        if (not _0rtt_enabled and hdr.type == NGTCP2_PKT_0RTT)
        {
            log::error(log_cat, "0-RTT is disabled for this endpoint; dropping 0-RTT packet");
            return nullptr;
        }

        assert(hdr.type == NGTCP2_PKT_INITIAL);

        ngtcp2_cid original_cid;
        ngtcp2_cid* pkt_original_cid = nullptr;
        ngtcp2_token_type token_type = NGTCP2_TOKEN_TYPE_UNKNOWN;  // 0

        if (hdr.tokenlen)
        {
            switch (hdr.token[0])
            {
                case NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY:
                    if (not verify_retry_token(pkt, &hdr, &original_cid))
                    {
                        send_stateless_connection_close(pkt, &hdr, io_error{NGTCP2_INVALID_TOKEN});
                        return nullptr;
                    }

                    pkt_original_cid = &original_cid;
                    token_type = NGTCP2_TOKEN_TYPE_RETRY;
                    break;
                case NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR:
                    if (not verify_token(pkt, &hdr))
                    {
                        send_retry(pkt, &hdr);
                        return nullptr;
                    }

                    token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
                    break;
                default:
                    if (hdr.dcid.datalen < NGTCP2_MIN_INITIAL_DCIDLEN)
                    {
                        send_stateless_connection_close(pkt, &hdr, io_error{NGTCP2_INVALID_TOKEN});
                        return nullptr;
                    }
                    send_retry(pkt, &hdr);
                    return nullptr;
            }
        }

        log::debug(log_cat, "Constructing path using packet path: {}", pkt.path);

        assert(in_event_loop());

        auto next_rid = next_reference_id();

        for (;;)
        {
            // emplace random CID into lookup keyed to unique reference ID
            if (auto [it_a, res_a] = conn_lookup.emplace(quic_cid::random(), next_rid); res_a)
            {
                if (auto [it_b, res_b] = conns.emplace(next_rid, nullptr); res_b)
                {
                    it_b->second = Connection::make_conn(
                            *this,
                            next_rid,
                            it_a->first,
                            hdr.scid,
                            pkt.path,
                            inbound_ctx,
                            inbound_alpns,
                            handshake_timeout,
                            std::nullopt,
                            &hdr,
                            token_type,
                            pkt_original_cid);

                    return it_b->second.get();
                }
            }
        }
    }

    io_result Endpoint::send_packets(const Path& path, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (_manual_routing)
        {
            return _manual_routing(path, bstring_view{buf, *bufsize}, n_pkts);
        }

        if (!socket)
        {
            log::warning(log_cat, "Cannot send packets on closed socket ({})", path);
            return io_result{EBADF};
        }

        assert(n_pkts >= 1 && n_pkts <= MAX_BATCH);

        log::trace(log_cat, "Sending {} UDP packet(s) {}...", n_pkts, path);

        auto [ret, sent] = socket->send(path, buf, bufsize, ecn, n_pkts);

        if (ret.failure() && !ret.blocked())
        {
            log::error(log_cat, "Error sending packets {}: {}", path, ret.str_error());
            n_pkts = 0;  // Drop any packets, as we had a serious error
            return ret;
        }

        if (sent < n_pkts)
        {
            if (sent == 0)  // Didn't send *any* packets, i.e. we got entirely blocked
                log::debug(log_cat, "UDP sent none of {}", n_pkts);

            else
            {
                // We sent some but not all, so shift the unsent packets back to the beginning of buf/bufsize
                log::debug(log_cat, "UDP undersent {}/{}", sent, n_pkts);
                size_t offset = std::accumulate(bufsize, bufsize + sent, size_t{0});
                size_t len = std::accumulate(bufsize + sent, bufsize + n_pkts, size_t{0});
                std::memmove(buf, buf + offset, len);
                std::copy(bufsize + sent, bufsize + n_pkts, bufsize);
                n_pkts -= sent;
            }

            // We always return EAGAIN (so that .blocked() is true) if we failed to send all, even
            // if that isn't strictly what we got back as the return value (sendmmsg gives back a
            // non-error on *partial* success).
            return io_result{EAGAIN};
        }
        else
            n_pkts = 0;

        return ret;
    }

    void Endpoint::send_or_queue_packet(
            const Path& p, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (not _manual_routing and !socket)
        {
            log::warning(log_cat, "Cannot sent to dead socket for path {}", p);
            if (callback)
                callback(io_result{EBADF});
            return;
        }

        size_t n_pkts = 1;
        size_t bufsize = buf.size();
        auto res = send_packets(p, buf.data(), &bufsize, ecn, n_pkts);

        if (res.blocked() and not _manual_routing)
        {
            socket->when_writeable([this, p, buf = std::move(buf), ecn, cb = std::move(callback)]() mutable {
                send_or_queue_packet(p, std::move(buf), ecn, std::move(cb));
            });
        }
        else if (callback)
            callback(res);
    }

    void Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, Path p)
    {
        uint8_t rint;
        gnutls_rnd(GNUTLS_RND_RANDOM, &rint, 8);
        std::vector<std::byte> buf;
        buf.resize(MAX_PMTUD_UDP_PAYLOAD);
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto nwrite = ngtcp2_pkt_write_version_negotiation(
                u8data(buf),
                buf.size(),
                rint,
                vid.dcid,
                vid.dcidlen,
                vid.scid,
                vid.scidlen,
                versions.data(),
                versions.size());
        if (nwrite <= 0)
        {
            log::warning(log_cat, "Error: Failed to construct version negotiation packet: {}", ngtcp2_strerror(nwrite));
            return;
        }

        assert(static_cast<size_t>(nwrite) <= buf.size());
        buf.resize(nwrite);

        send_or_queue_packet(p, std::move(buf), /*ecn=*/0);
    }

    void Endpoint::check_timeouts()
    {
        auto now = get_time();

        for (auto it_a = draining_closing.begin(); it_a != draining_closing.end();)
        {
            if (it_a->first < now)
            {
                if (auto it_b = conns.find(it_a->second); it_b != conns.end())
                {
                    log::debug(log_cat, "Deleting closing/draining connection ({})", it_b->first);
                    delete_connection(*it_b->second.get());
                }

                it_a = draining_closing.erase(it_a);
            }
            else
                ++it_a;
        }

        // Propagate the timeout check to connections, to be propagated to streams
        for (auto& [cid, conn] : conns)
            conn->check_stream_timeouts();
    }

    std::shared_ptr<connection_interface> Endpoint::get_conn(ConnectionID rid)
    {
        if (auto it = conns.find(rid); it != conns.end())
            return it->second;

        return nullptr;
    }

    Connection* Endpoint::get_conn(const quic_cid& id)
    {
        if (auto it_a = conn_lookup.find(id); it_a != conn_lookup.end())
        {
            if (auto it_b = conns.find(it_a->second); it_b != conns.end())
                return it_b->second.get();
        }

        return nullptr;
    }

    bool Endpoint::in_event_loop() const
    {
        return net.in_event_loop();
    }

}  // namespace oxen::quic
